package scanner

import "testing"

// The services.ewa.bh false positive: a CNAME to a live AWS ALB was matched as a
// dangling S3 bucket by the old catch-all "amazonaws.com" pattern.
func TestTakeoverFingerprintDoesNotMatchELB(t *testing.T) {
	elb := "customer-service-system-alb-1447939680.eu-west-1.elb.amazonaws.com"
	if fp := matchTakeoverFingerprint(elb); fp != nil {
		t.Fatalf("an ELB/ALB name must not match any takeover fingerprint, matched %q", fp.service)
	}
	if !awsNonTakeoverableInfra(elb) {
		t.Fatal("ELB name must be recognised as non-takeoverable AWS infrastructure")
	}
}

func TestTakeoverFingerprintStillMatchesRealServices(t *testing.T) {
	cases := map[string]string{
		"mybucket.s3.amazonaws.com":                   "AWS S3",
		"mybucket.s3-website-eu-west-1.amazonaws.com": "AWS S3",
		"mybucket.s3.eu-west-1.amazonaws.com":         "AWS S3",
		"someorg.github.io":                           "GitHub Pages",
		"app.herokuapp.com":                           "Heroku",
		"site.azurewebsites.net":                      "Azure",
	}
	for cname, want := range cases {
		fp := matchTakeoverFingerprint(cname)
		if fp == nil {
			t.Errorf("%s: expected a %s match, got nil", cname, want)
			continue
		}
		if fp.service != want {
			t.Errorf("%s: expected %s, got %s", cname, want, fp.service)
		}
		if awsNonTakeoverableInfra(cname) {
			t.Errorf("%s: real claimable service must NOT be treated as non-takeoverable infra", cname)
		}
	}
}

// The core rule: no dangling signal ⇒ score 0 (dropped). This is exactly the
// ewa.bh case (sigMatch=false, nx=false, subzy=false).
func TestTakeoverConfidence(t *testing.T) {
	cases := []struct {
		sig, nx, subzy bool
		want           int
	}{
		{false, false, false, 0},              // live/claimed resource → drop (the FP)
		{true, false, false, ConfEvidence},    // unclaimed-body signature
		{false, true, false, ConfCandidateHi}, // CNAME target NXDOMAIN
		{false, false, true, ConfEvidence},    // subzy confirms
		{true, true, false, ConfMultiTool},    // body + DNS
		{true, false, true, ConfMultiTool},    // body + subzy
	}
	for _, c := range cases {
		if got := takeoverConfidence(c.sig, c.nx, c.subzy, false); got != c.want {
			t.Errorf("takeoverConfidence(sig=%v nx=%v subzy=%v) = %d, want %d", c.sig, c.nx, c.subzy, got, c.want)
		}
	}
}

// A generic signature (Cargo's "404 Not Found", Unbounce's Apache-boilerplate
// phrase) must never be trusted alone — it is the exact shape of a false
// positive, since it is also the default body of countless unrelated 404
// pages. Only paired with NXDOMAIN or a second tool's confirmation does it
// count as real evidence.
func TestTakeoverConfidenceGenericSignatureRequiresCorroboration(t *testing.T) {
	cases := []struct {
		name           string
		sig, nx, subzy bool
		want           int
	}{
		{"generic body alone -> dropped (the false positive)", true, false, false, 0},
		{"generic body + NXDOMAIN -> trusted", true, true, false, ConfMultiTool},
		{"generic body + subzy -> trusted", true, false, true, ConfMultiTool},
		{"NXDOMAIN alone (no body match) -> unaffected by genericity", false, true, false, ConfCandidateHi},
	}
	for _, c := range cases {
		if got := takeoverConfidence(c.sig, c.nx, c.subzy, true); got != c.want {
			t.Errorf("%s: takeoverConfidence(sig=%v nx=%v subzy=%v generic=true) = %d, want %d", c.name, c.sig, c.nx, c.subzy, got, c.want)
		}
	}
}

func TestCargoAndUnbounceFingerprintsAreMarkedGeneric(t *testing.T) {
	for _, svc := range []string{"Cargo", "Unbounce", "Statuspage"} {
		found := false
		for _, fp := range takeoverFingerprints {
			if fp.service == svc {
				found = true
				if !fp.generic {
					t.Errorf("%s's signature %q is a stock/generic error phrase and must be marked generic", svc, fp.signature)
				}
			}
		}
		if !found {
			t.Errorf("expected a fingerprint entry for %s", svc)
		}
	}
}
