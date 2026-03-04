package tests

// engine_test.go — unit tests for the L7 engine verdict logic.
//
// Tests cover:
//   1. SNI parsing correctness (synthetic ClientHello bytes)
//   2. Decide() policy: block/allow per SNI, HTTP Host, and no-identifier cases
//   3. Real-world shared-IP scenarios:
//      - google.com / maps.google.com / mail.google.com / drive.google.com
//        (block maps.google.com → check others still allowed)
//      - www.android.com / marketingplatform.google.com
//        (block one, allow the other)
//      - IMT / IP-Paris university cluster (multiple services, shared reverse proxies)
//
// None of these tests open network connections or require root.
// They exercise only the pure Decide() function and SNI parser.

import (
	"encoding/binary"
	"testing"
)

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

// newTestEngine builds an Engine with no hub/logger (safe for unit tests:
// hub and logger are only used in emitLog, which Decide() never calls).
func newTestEngine() *Engine {
	return &Engine{
		sharedFQDNs: make(map[string]map[string]struct{}),
		sharedIPs:   make(map[string]struct{}),
	}
}

// block registers fqdn as blocked on interface "eth0".
func (e *Engine) block(fqdn string) {
	e.AddSharedFQDN("wlp8s0", fqdn)
}

// sharedIP registers ip as a shared-L7 IP.
func (e *Engine) sharedIP(ip string) {
	e.AddSharedIP(ip)
}

// buildClientHello constructs a minimal TLS 1.3 ClientHello with a single SNI entry.
// The returned slice starts at the ClientHello body (after the 4-byte handshake header),
// matching what parseSNIFromClientHello expects.
func buildClientHello(sni string) []byte {
	sniBytes := []byte(sni)
	nameLen := len(sniBytes)

	// SNI extension value:
	//   2 bytes: SNI list length  (nameLen + 3)
	//   1 byte:  entry type       (0x00 = host_name)
	//   2 bytes: name length      (nameLen)
	//   N bytes: name
	sniValue := make([]byte, 0, 5+nameLen)
	sniValue = append(sniValue,
		byte((nameLen+3)>>8), byte(nameLen+3), // list length
		0x00,                            // type host_name
		byte(nameLen>>8), byte(nameLen), // name length
	)
	sniValue = append(sniValue, sniBytes...)

	// Extension:
	//   2 bytes: type  (0x0000 = SNI)
	//   2 bytes: length (len(sniValue))
	//   N bytes: value
	ext := make([]byte, 0, 4+len(sniValue))
	ext = append(ext, 0x00, 0x00) // ext type SNI
	ext = appendU16(ext, uint16(len(sniValue)))
	ext = append(ext, sniValue...)

	// ClientHello body:
	hello := make([]byte, 0)
	hello = append(hello, 0x03, 0x03)       // legacy version TLS 1.2
	hello = append(hello, make([]byte, 32)...) // random (32 bytes)
	hello = append(hello, 0x00)              // session ID length = 0
	hello = append(hello, 0x00, 0x02)        // cipher suites length = 2
	hello = append(hello, 0xc0, 0x2b)        // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	hello = append(hello, 0x01, 0x00)        // compression methods: 1 method, null
	hello = appendU16(hello, uint16(len(ext))) // extensions length
	hello = append(hello, ext...)
	return hello
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// ─────────────────────────────────────────────
// 1. SNI parser unit tests
// ─────────────────────────────────────────────

func TestParseSNI_Correct(t *testing.T) {
	cases := []string{
		"example.com",
		"maps.google.com",
		"moodle.ip-paris.fr",
		"z.imt.fr",
		"followme.imtbs-tsp.eu",
		"trombi.imtbs-tsp.eu",
		"virtlabs.imtbs-tsp.eu",
		"glpi.imtbs-tsp.eu",
		"mediaserver.ip-paris.fr",
		"extra.u-picardie.fr",
		"u-picardie.fr",
		"ledvance.ewyse.agency",
	}
	for _, sni := range cases {
		got := ParseSNIFromClientHello(buildClientHello(sni))
		if got != sni {
			t.Errorf("SNI parse: want %q, got %q", sni, got)
		}
	}
}

func TestParseSNI_Empty(t *testing.T) {
	cases := [][]byte{
		{},
		make([]byte, 5),
		make([]byte, 37), // too short for hello body
	}
	for _, b := range cases {
		if got := ParseSNIFromClientHello(b); got != "" {
			t.Errorf("expected empty SNI for short input, got %q", got)
		}
	}
}

func TestParseSNI_NoSNIExtension(t *testing.T) {
	// Build a ClientHello with an unrelated extension only (heartbeat, type 0x000f)
	ext := []byte{0x00, 0x0f, 0x00, 0x01, 0x01} // type=15, len=1, value=1
	hello := make([]byte, 0)
	hello = append(hello, 0x03, 0x03)
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0x00)       // session ID len
	hello = append(hello, 0x00, 0x02) // ciphers len
	hello = append(hello, 0xc0, 0x2b)
	hello = append(hello, 0x01, 0x00) // compression
	hello = appendU16(hello, uint16(len(ext)))
	hello = append(hello, ext...)
	if got := ParseSNIFromClientHello(hello); got != "" {
		t.Errorf("expected empty SNI when no SNI extension, got %q", got)
	}
}

// ─────────────────────────────────────────────
// 2. Decide() — SNI-based policy
// ─────────────────────────────────────────────

func TestDecide_SNIBlocked(t *testing.T) {
	e := newTestEngine()
	e.block("maps.google.com")
	e.sharedIP("142.250.179.110") // hypothetical shared Google IP

	if v := e.Decide("maps.google.com", "", "142.250.179.110"); v != VerdictDrop {
		t.Errorf("maps.google.com SNI: want drop, got %s", v)
	}
}

func TestDecide_SNIAllowed_WhenOnlyOneBlocked(t *testing.T) {
	e := newTestEngine()
	e.block("maps.google.com")
	e.sharedIP("142.250.179.110")

	allowed := []string{
		"google.com",
		"mail.google.com",
		"drive.google.com",
	}
	for _, sni := range allowed {
		if v := e.Decide(sni, "", "142.250.179.110"); v != VerdictAccept {
			t.Errorf("SNI %q: want accept (not in block list), got %s", sni, v)
		}
	}
}

func TestDecide_AndroidVsMarketingPlatform(t *testing.T) {
	// www.android.com and marketingplatform.google.com share a Google IP.
	// Block marketingplatform, verify android.com is still allowed.
	e := newTestEngine()
	e.block("marketingplatform.google.com")
	e.sharedIP("142.250.179.132")

	if v := e.Decide("marketingplatform.google.com", "", "142.250.179.132"); v != VerdictDrop {
		t.Errorf("marketingplatform.google.com: want drop, got %s", v)
	}
	if v := e.Decide("www.android.com", "", "142.250.179.132"); v != VerdictAccept {
		t.Errorf("www.android.com: want accept (not blocked), got %s", v)
	}
}

func TestDecide_BlockAllGoogleSubdomains(t *testing.T) {
	// Block all four Google properties sharing an IP.
	e := newTestEngine()
	e.block("google.com")
	e.block("maps.google.com")
	e.block("mail.google.com")
	e.block("drive.google.com")
	e.sharedIP("142.250.179.110")

	for _, sni := range []string{"google.com", "maps.google.com", "mail.google.com", "drive.google.com"} {
		if v := e.Decide(sni, "", "142.250.179.110"); v != VerdictDrop {
			t.Errorf("%q: want drop, got %s", sni, v)
		}
	}
}

// ─────────────────────────────────────────────
// 3. Decide() — HTTP Host header policy
// ─────────────────────────────────────────────

func TestDecide_HTTPHostBlocked(t *testing.T) {
	e := newTestEngine()
	e.block("maps.google.com")
	e.sharedIP("142.250.179.110")

	// No SNI (plain HTTP), Host header present
	if v := e.Decide("", "maps.google.com", "142.250.179.110"); v != VerdictDrop {
		t.Errorf("HTTP Host blocked: want drop, got %s", v)
	}
}

func TestDecide_HTTPHostAllowed(t *testing.T) {
	e := newTestEngine()
	e.block("maps.google.com")
	e.sharedIP("142.250.179.110")

	if v := e.Decide("", "drive.google.com", "142.250.179.110"); v != VerdictAccept {
		t.Errorf("drive.google.com HTTP Host: want accept, got %s", v)
	}
}

// ─────────────────────────────────────────────
// 4. Decide() — no-identifier (no SNI, no Host)
// ─────────────────────────────────────────────

func TestDecide_NoIdentifier_SharedIP_Drops(t *testing.T) {
	e := newTestEngine()
	e.block("maps.google.com")
	e.sharedIP("142.250.179.110")

	// No SNI, no Host → shared IP → must drop
	if v := e.Decide("", "", "142.250.179.110"); v != VerdictDrop {
		t.Errorf("no-identifier on shared IP: want drop, got %s", v)
	}
}

func TestDecide_NoIdentifier_NonSharedIP_Passes(t *testing.T) {
	e := newTestEngine()
	e.block("maps.google.com")
	// 8.8.8.8 is NOT registered as shared
	if v := e.Decide("", "", "8.8.8.8"); v != VerdictAccept {
		t.Errorf("no-identifier on non-shared IP: want accept, got %s", v)
	}
}

func TestDecide_NoIdentifier_EmptyIP_Passes(t *testing.T) {
	e := newTestEngine()
	e.sharedIP("142.250.179.110")
	if v := e.Decide("", "", ""); v != VerdictAccept {
		t.Errorf("no-identifier, empty IP: want accept, got %s", v)
	}
}

// ─────────────────────────────────────────────
// 5. IMT / IP-Paris university cluster
//
// Real topology: multiple service FQDNs (service.domain) alias to shared
// reverse-proxy IPs (rproxy.*, zproxy.*, frontend*, etc.).
// We want to block some services while allowing others on the same IP.
// ─────────────────────────────────────────────

// imtSharedIP is a stand-in for the shared reverse-proxy address used by
// the IMT cluster services (actual IP determined at runtime by DNS; we use
// a fixed value here to test policy isolation without network calls).
const imtSharedIP = "195.221.100.10"

func setupIMTEngine() *Engine {
	e := newTestEngine()
	// All IMT services share a reverse-proxy IP
	e.sharedIP(imtSharedIP)

	// Block a subset
	e.block("moodle.ip-paris.fr")
	e.block("z.imt.fr")
	e.block("glpi.imtbs-tsp.eu")
	e.block("mediaserver.ip-paris.fr")

	// Allow the rest (not registered → engine accepts by default)
	// followme.imtbs-tsp.eu, trombi.imtbs-tsp.eu, virtlabs.imtbs-tsp.eu,
	// extra.u-picardie.fr, u-picardie.fr
	return e
}

func TestIMT_BlockedServices(t *testing.T) {
	e := setupIMTEngine()
	blocked := []string{
		"moodle.ip-paris.fr",
		"z.imt.fr",
		"glpi.imtbs-tsp.eu",
		"mediaserver.ip-paris.fr",
	}
	for _, sni := range blocked {
		if v := e.Decide(sni, "", imtSharedIP); v != VerdictDrop {
			t.Errorf("IMT blocked service %q: want drop, got %s", sni, v)
		}
	}
}

func TestIMT_AllowedServices(t *testing.T) {
	e := setupIMTEngine()
	allowed := []string{
		"followme.imtbs-tsp.eu",
		"trombi.imtbs-tsp.eu",
		"virtlabs.imtbs-tsp.eu",
		"extra.u-picardie.fr",
		"u-picardie.fr",
	}
	for _, sni := range allowed {
		if v := e.Decide(sni, "", imtSharedIP); v != VerdictAccept {
			t.Errorf("IMT allowed service %q: want accept, got %s", sni, v)
		}
	}
}

func TestIMT_NoSNI_DirectIP_Drops(t *testing.T) {
	e := setupIMTEngine()
	// Direct connection to the reverse-proxy IP with no SNI — must drop
	// because the IP hosts blocked domains and we cannot determine intent.
	if v := e.Decide("", "", imtSharedIP); v != VerdictDrop {
		t.Errorf("IMT direct IP no-SNI: want drop, got %s", v)
	}
}

func TestIMT_AliasesNotInBlockList(t *testing.T) {
	// Aliases (keepalived.int-evry.fr, zproxy.enst.fr, etc.) are the backend
	// names — if a client somehow sends these as SNI, they are NOT in the block
	// list (we block the service name, not the backend alias).
	e := setupIMTEngine()
	aliases := []string{
		"keepalived.int-evry.fr",
		"rproxy.ip-paris.cblue.be",
		"zproxy.enst.fr",
		"frontend2025.int-evry.fr",
		"trombi.int-evry.fr",
		"virtlabs.int-evry.fr",
		"glpi.int-evry.fr",
		"ubicast.tv",
		"webfront.u-picardie.fr",
	}
	for _, alias := range aliases {
		if v := e.Decide(alias, "", imtSharedIP); v != VerdictAccept {
			t.Errorf("alias %q should not be blocked (we block service names, not backends), got %s", alias, v)
		}
	}
}

// ─────────────────────────────────────────────
// 6. Case insensitivity
// ─────────────────────────────────────────────

func TestDecide_CaseInsensitive(t *testing.T) {
	e := newTestEngine()
	e.block("Maps.Google.COM")

	// Regardless of case in SNI or block list, verdict must be consistent
	for _, sni := range []string{"maps.google.com", "MAPS.GOOGLE.COM", "Maps.Google.Com"} {
		if v := e.Decide(sni, "", ""); v != VerdictDrop {
			t.Errorf("case insensitive block: %q → want drop, got %s", sni, v)
		}
	}
}

// ─────────────────────────────────────────────
// 7. SNI takes precedence over dstIP
// ─────────────────────────────────────────────

func TestDecide_SNIWinOverSharedIP(t *testing.T) {
	// dstIP is shared (would drop with no-identifier),
	// but SNI is present and not blocked → must accept.
	e := newTestEngine()
	e.block("maps.google.com")
	e.sharedIP("142.250.179.110")

	// drive.google.com SNI on a shared IP → allow
	if v := e.Decide("drive.google.com", "", "142.250.179.110"); v != VerdictAccept {
		t.Errorf("SNI not-blocked on shared IP: want accept, got %s", v)
	}
}

// ─────────────────────────────────────────────
// 8. Remove rule mid-flight
// ─────────────────────────────────────────────

func TestDecide_RemoveUnblocks(t *testing.T) {
	e := newTestEngine()
	e.block("maps.google.com")
	e.sharedIP("142.250.179.110")

	if v := e.Decide("maps.google.com", "", "142.250.179.110"); v != VerdictDrop {
		t.Fatal("pre-remove: want drop")
	}

	e.RemoveSharedFQDN("eth0", "maps.google.com")

	if v := e.Decide("maps.google.com", "", "142.250.179.110"); v != VerdictAccept {
		t.Errorf("post-remove: want accept, got %s", v)
	}
}

// ─────────────────────────────────────────────
// 9. Add/Remove SharedIP
// ─────────────────────────────────────────────

func TestDecide_RemoveSharedIP_AllowsNoSNI(t *testing.T) {
	e := newTestEngine()
	e.block("maps.google.com")
	e.sharedIP("142.250.179.110")

	if v := e.Decide("", "", "142.250.179.110"); v != VerdictDrop {
		t.Fatal("pre-remove shared IP: want drop")
	}

	e.RemoveSharedIP("142.250.179.110")

	// Now the IP is no longer shared → no-identifier → accept
	if v := e.Decide("", "", "142.250.179.110"); v != VerdictAccept {
		t.Errorf("post-remove shared IP: want accept, got %s", v)
	}
}

// ─────────────────────────────────────────────
// 10. Raw SNI bytes → ClientHello → parse round-trip
// ─────────────────────────────────────────────

func TestSNIRoundTrip_AllRealDomains(t *testing.T) {
	domains := []string{
		"google.com",
		"maps.google.com",
		"mail.google.com",
		"drive.google.com",
		"www.android.com",
		"marketingplatform.google.com",
		"moodle.ip-paris.fr",
		"z.imt.fr",
		"followme.imtbs-tsp.eu",
		"trombi.imtbs-tsp.eu",
		"virtlabs.imtbs-tsp.eu",
		"glpi.imtbs-tsp.eu",
		"mediaserver.ip-paris.fr",
		"extra.u-picardie.fr",
		"u-picardie.fr",
		"keepalived.int-evry.fr",
		"rproxy.ip-paris.cblue.be",
		"zproxy.enst.fr",
	}
	for _, domain := range domains {
		hello := buildClientHello(domain)
		got := ParseSNIFromClientHello(hello)
		if got != domain {
			t.Errorf("round-trip %q: got %q", domain, got)
		}
	}
}

// ─────────────────────────────────────────────
// 11. Verify binary layout of buildClientHello
//     (ensures our helper matches the parser's expectations)
// ─────────────────────────────────────────────

func TestBuildClientHello_Layout(t *testing.T) {
	sni := "test.example.org"
	hello := buildClientHello(sni)

	// Offset 0: legacy version (2 bytes)
	if hello[0] != 0x03 || hello[1] != 0x03 {
		t.Errorf("version: want 0x0303, got 0x%02x%02x", hello[0], hello[1])
	}

	// Offset 2..33: random (32 bytes), offset 34: session ID len = 0
	if hello[34] != 0x00 {
		t.Errorf("session ID len: want 0, got %d", hello[34])
	}

	// Check cipher suites length = 2
	cipherLen := binary.BigEndian.Uint16(hello[35:37])
	if cipherLen != 2 {
		t.Errorf("cipher suites len: want 2, got %d", cipherLen)
	}

	// Verify SNI parses back correctly
	got := ParseSNIFromClientHello(hello)
	if got != sni {
		t.Errorf("layout check: got SNI %q, want %q", got, sni)
	}
}