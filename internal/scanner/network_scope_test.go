package scanner

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeAndExpandNetworkScope(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"192.168.1.1", []string{"192.168.1.1"}},
		{"192.168.1.0/30", []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}},
		{"192.168.1.1-192.168.1.3", []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}},
	} {
		got, err := ExpandNetworkScope(tc.in, 32)
		if err != nil {
			t.Fatalf("ExpandNetworkScope(%q): %v", tc.in, err)
		}
		var text []string
		for _, ip := range got {
			text = append(text, ip.String())
		}
		if !reflect.DeepEqual(text, tc.want) {
			t.Fatalf("ExpandNetworkScope(%q)=%v, want %v", tc.in, text, tc.want)
		}
	}
}

func TestNetworkScopeRejectsReversedRangeAndOversizeCIDR(t *testing.T) {
	for _, raw := range []string{"192.168.1.9-192.168.1.1", "10.0.0.0/8"} {
		if _, err := ExpandNetworkScope(raw, 256); err == nil {
			t.Fatalf("scope %q unexpectedly accepted", raw)
		}
	}
}

// A hostname is a common, legitimate Network Scanner input — the operator's
// asset is very often a domain, not its IP — so it resolves via DNS instead
// of being rejected outright. "localhost" resolves through the hosts
// file/NSS rather than a live query, keeping this deterministic in CI.
func TestNetworkScopeResolvesAHostname(t *testing.T) {
	got, err := ExpandNetworkScope("localhost", 32)
	if err != nil {
		t.Fatalf("ExpandNetworkScope(%q): %v", "localhost", err)
	}
	if len(got) == 0 {
		t.Fatalf("ExpandNetworkScope(%q) resolved to no addresses", "localhost")
	}
	for _, ip := range got {
		if ip.String() != "127.0.0.1" && ip.String() != "::1" {
			t.Fatalf("ExpandNetworkScope(%q) resolved to unexpected address %s", "localhost", ip)
		}
	}
}

// A garbage, unresolvable hostname-shaped token still fails cleanly — the
// fallback is bounded (it can't hang) and never silently drops the scope.
func TestNetworkScopeRejectsUnresolvableHostname(t *testing.T) {
	if _, err := ExpandNetworkScope("this-host-does-not-exist.invalid", 32); err == nil {
		t.Fatalf("scope unexpectedly accepted an unresolvable hostname")
	}
}

// A malformed range/CIDR is all digits/dots/hyphens/slashes — never a
// letter — so it must never be misread as a hostname and sent to DNS; the
// original, more specific parse error is what the operator should see.
func TestNetworkScopeNeverSendsMalformedIPSyntaxToDNS(t *testing.T) {
	_, err := ExpandNetworkScope("192.168.1.9-192.168.1.1", 256)
	if err == nil {
		t.Fatalf("expected an error for a reversed range")
	}
	if strings.Contains(err.Error(), "resolved") {
		t.Fatalf("reversed range was misread as a hostname and sent to DNS: %v", err)
	}
}

func TestFilterCDNWAFBlocksKnownCloudflareRangeButKeepsPrivate(t *testing.T) {
	kept, blocked := FilterCDNWAF([]net.IP{net.ParseIP("173.245.48.12"), net.ParseIP("192.168.1.1")})
	if len(blocked) != 1 || blocked[0].IP != "173.245.48.12" || (blocked[0].Kind != "cdn" && blocked[0].Kind != "waf") {
		t.Fatalf("blocked=%+v", blocked)
	}
	if !reflect.DeepEqual(kept, []string{"192.168.1.1"}) {
		t.Fatalf("kept=%v", kept)
	}
}
