package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// network_brute_tools.go — the tool-backed half of the per-service credential
// audit (network_brute.go holds the native-Go half: SSH/FTP/MySQL/PostgreSQL/
// Redis). RDP, VNC, Telnet and SMB have no safe, dependency-light native
// implementation — RDP/SMB need a full NTLM/CredSSP handshake, VNC a bounded
// but still binary RFB challenge-response — so these four are proven instead
// with ncrack (rdp/vnc/telnet) and hydra (smb), two purpose-built, widely
// audited network-login crackers. Both are OPTIONAL external tools: every
// module here degrades to BlockedPhase when its tool is unavailable, exactly
// like every other optional tool in Reconner.
//
// Authorization, scoping, rate-limiting and the stop-on-first-hit discipline
// are IDENTICAL to the native modules: never guesses a port (only targets
// services this scan's own fingerprint pass already verified open and
// identified by name), gated by networkAuthorized(), a bounded user list, a
// capped password subset, and the underlying process is killed the instant a
// credential is confirmed (see runToolCred) rather than left to exhaust every
// remaining combination.

// netToolMaxPasswords caps how many of the 1000-password corpus these four
// TOOL-backed modules try per target. RDP/SMB in particular commonly enforce
// real account-lockout policies (unlike XML-RPC or a bare TCP banner), so a
// smaller, higher-signal subset is the responsible default — this is on top
// of, not instead of, each tool's own per-target stop-on-first-hit behaviour.
const netToolMaxPasswords = 200

var (
	netUsersRDP    = []string{"administrator", "admin", "root"}
	netUsersTelnet = []string{"admin", "root", "user"}
	netUsersSMB    = []string{"administrator", "admin", "guest"}
	netUsersVNC    = []string{"vnc"} // VNC's classic RFB auth is password-only; the module ignores this value
)

// toolCredResult is a confirmed hit from ncrack or hydra.
type toolCredResult struct {
	User, Pass string
}

// runToolCred shells out to a credential-cracking tool, streams its output,
// and stops the PROCESS the instant a confirmed hit matches extractor — proof
// obtained, no reason to keep trying further combinations against this
// target. extractor receives the full accumulated output on every new line
// (not just that line) so a tool whose success report spans multiple lines is
// still matched correctly.
func (s *NetworkScanner) runToolCred(ctx context.Context, tool string, args []string, extractor func(accumulated string) (toolCredResult, bool)) (toolCredResult, bool) {
	if s.exec == nil || !s.exec.IsToolAvailable(tool) {
		return toolCredResult{}, false
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu     sync.Mutex
		buf    strings.Builder
		result toolCredResult
		found  bool
	)
	_ = s.exec.RunWithCallback(cctx, "network-cred-"+tool+"-"+strconv.FormatInt(time.Now().UnixNano(), 36), func(line string) {
		mu.Lock()
		defer mu.Unlock()
		if found {
			return
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
		if r, ok := extractor(buf.String()); ok {
			result, found = r, true
			cancel() // credential confirmed — stop the process immediately
		}
	}, tool, args...)
	mu.Lock()
	defer mu.Unlock()
	return result, found
}

// ── ncrack-backed: RDP / VNC / Telnet ───────────────────────────────────────

var ncrackHitRe = regexp.MustCompile(`(?i)(rdp|vnc|telnet)[:\s].*?'([^']*)'\s*'([^']*)'`)

func ncrackExtractor(service string) func(string) (toolCredResult, bool) {
	return func(accumulated string) (toolCredResult, bool) {
		for _, m := range ncrackHitRe.FindAllStringSubmatch(accumulated, -1) {
			if strings.EqualFold(m[1], service) {
				return toolCredResult{User: m[2], Pass: m[3]}, true
			}
		}
		return toolCredResult{}, false
	}
}

// runNcrack builds and runs one ncrack invocation against a single ip:port,
// bounded to the given users/passwords, and returns a confirmed hit (if any).
func (s *NetworkScanner) runNcrack(ctx context.Context, service, ip string, port int, users, passwords []string) (toolCredResult, bool) {
	userFile, err := writeTempLines("reconner-ncrack-users", users)
	if err != nil {
		return toolCredResult{}, false
	}
	defer os.Remove(userFile)
	passFile, err := writeTempLines("reconner-ncrack-pass", passwords)
	if err != nil {
		return toolCredResult{}, false
	}
	defer os.Remove(passFile)

	args := []string{
		"-d", "0", // quiet-ish; we parse stdout, not a log file
		"-p", strconv.Itoa(port),
		"-U", userFile,
		"-P", passFile,
		ip,
	}
	return s.runToolCred(ctx, "ncrack", args, ncrackExtractor(service))
}

func (s *NetworkScanner) runProtocolToolAudit(
	ctx context.Context, targetID, module, rawScope string,
	serviceNames []string,
	users []string, run func(ip string, port int, users, passwords []string) (toolCredResult, bool),
	vulnType, replayTemplate string, logFn LogFunc,
) error {
	if !s.guardAuthorized(ctx, module, logFn) {
		return ctx.Err()
	}
	targets, err := s.loadNetCredTargets(ctx, targetID, rawScope, serviceNames...)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return BlockedPhase("no verified " + strings.Join(serviceNames, "/") + " service in scope for the credential audit")
	}
	passwords := s.netPasswords()
	if len(passwords) > netToolMaxPasswords {
		passwords = passwords[:netToolMaxPasswords]
	}
	hits := 0
	for _, tgt := range targets {
		if ctx.Err() != nil {
			break
		}
		res, ok := run(tgt.IP, tgt.Port, users, passwords)
		if !ok {
			continue
		}
		addr := net.JoinHostPort(tgt.IP, strconv.Itoa(tgt.Port))
		poc := fmt.Sprintf(replayTemplate, addr, res.User, res.Pass)
		evidence := "Valid credential confirmed for user '" + res.User + "' (password " + maskSecret(res.Pass) + ") on " + addr +
			". This grants direct access to the service — typically full compromise of the host/session. Rotate the credential and restrict network access to trusted sources."
		_, _ = RecordDetectorObservation(ctx, s.db, DetectorObservation{
			TargetID: targetID, Type: vulnType, Severity: "critical",
			URL: addr, Method: "TCP", Parameter: res.User, Location: "auth",
			Payload: poc, Evidence: evidence, Source: module,
			DetectionMethod: "network:" + vulnType, Confidence: 100, Priority: 500,
			Verdict: VerifyVerified,
		})
		hits++
	}
	logFn("warn", module, fmt.Sprintf("Credential audit done over %d target(s). %d valid credential(s) found.", len(targets), hits))
	return ctx.Err()
}

// RunBruteRDP implements network_brute_rdp (ncrack).
func (s *NetworkScanner) RunBruteRDP(ctx context.Context, targetID, rawScope string, logFn LogFunc) error {
	run := func(ip string, port int, users, passwords []string) (toolCredResult, bool) {
		return s.runNcrack(ctx, "rdp", ip, port, users, passwords)
	}
	return s.runProtocolToolAudit(ctx, targetID, "network_brute_rdp", rawScope, []string{"ms-wbt-server"},
		netUsersRDP, run, "network_rdp_weak_credentials",
		"ncrack -p rdp:3389 -u %[2]s -P <passwords> %[1]s  # confirmed password: %[3]s", logFn)
}

// RunBruteVNC implements network_brute_vnc (ncrack).
func (s *NetworkScanner) RunBruteVNC(ctx context.Context, targetID, rawScope string, logFn LogFunc) error {
	run := func(ip string, port int, users, passwords []string) (toolCredResult, bool) {
		return s.runNcrack(ctx, "vnc", ip, port, users, passwords)
	}
	return s.runProtocolToolAudit(ctx, targetID, "network_brute_vnc", rawScope, []string{"vnc"},
		netUsersVNC, run, "network_vnc_weak_credentials",
		"ncrack -p vnc:5900 -P <passwords> %[1]s  # confirmed password: %[3]s", logFn)
}

// RunBruteTelnet implements network_brute_telnet (ncrack).
func (s *NetworkScanner) RunBruteTelnet(ctx context.Context, targetID, rawScope string, logFn LogFunc) error {
	run := func(ip string, port int, users, passwords []string) (toolCredResult, bool) {
		return s.runNcrack(ctx, "telnet", ip, port, users, passwords)
	}
	return s.runProtocolToolAudit(ctx, targetID, "network_brute_telnet", rawScope, []string{"telnet"},
		netUsersTelnet, run, "network_telnet_weak_credentials",
		"ncrack -p telnet:23 -u %[2]s -P <passwords> %[1]s  # confirmed password: %[3]s", logFn)
}

// ── hydra-backed: SMB ────────────────────────────────────────────────────────

// hydraHitRe matches hydra's canonical success line:
//
//	[445][smb2] host: 10.0.0.5   login: administrator   password: hunter2
var hydraHitRe = regexp.MustCompile(`(?i)\[\d+]\[\S+]\s+host:\s*\S+\s+login:\s*(.*?)\s+password:\s*(.+?)\s*$`)

func hydraExtractor(accumulated string) (toolCredResult, bool) {
	sc := bufio.NewScanner(strings.NewReader(accumulated))
	for sc.Scan() {
		if m := hydraHitRe.FindStringSubmatch(sc.Text()); m != nil {
			return toolCredResult{User: m[1], Pass: m[2]}, true
		}
	}
	return toolCredResult{}, false
}

// RunBruteSMB implements network_brute_smb (hydra).
func (s *NetworkScanner) RunBruteSMB(ctx context.Context, targetID, rawScope string, logFn LogFunc) error {
	run := func(ip string, port int, users, passwords []string) (toolCredResult, bool) {
		userFile, err := writeTempLines("reconner-hydra-users", users)
		if err != nil {
			return toolCredResult{}, false
		}
		defer os.Remove(userFile)
		passFile, err := writeTempLines("reconner-hydra-pass", passwords)
		if err != nil {
			return toolCredResult{}, false
		}
		defer os.Remove(passFile)
		args := []string{
			"-L", userFile,
			"-P", passFile,
			"-t", "4", "-W", "2", "-f", // 4 parallel tasks, 2s wait, stop at first hit
			"-s", strconv.Itoa(port),
			ip, "smb2",
		}
		return s.runToolCred(ctx, "hydra", args, hydraExtractor)
	}
	return s.runProtocolToolAudit(ctx, targetID, "network_brute_smb", rawScope, []string{"microsoft-ds", "netbios-ssn"},
		netUsersSMB, run, "network_smb_weak_credentials",
		"hydra -L <users> -P <passwords> -s <port> %[1]s smb2  # confirmed login: %[2]s / password: %[3]s", logFn)
}
