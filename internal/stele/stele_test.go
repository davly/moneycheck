package stele

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fixedDigest returns a deterministic non-zero ledger digest for tests.
func fixedDigest() [sha256.Size]byte {
	var d [sha256.Size]byte
	for i := range d {
		d[i] = byte(i + 1)
	}
	return d
}

// fakeChecker is a SelfChecker test double that records invocations.
type fakeChecker struct {
	calls   int
	entries int
	digest  [sha256.Size]byte
	err     error
}

func (f *fakeChecker) SelfCheck() (int, [sha256.Size]byte, error) {
	f.calls++
	return f.entries, f.digest, f.err
}

// TestNewRunAnchorPayloadShape pins every field of the anchor verdict —
// the honesty contract is load-bearing (self-check labelling, LIT-only-
// after-pass, subject_hash binding).
func TestNewRunAnchorPayloadShape(t *testing.T) {
	digest := fixedDigest()
	sealedAt := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	v := NewRunAnchor("decide", 1, digest, sealedAt)

	wantHex := hex.EncodeToString(digest[:])
	if v.Substrate != "flagships/moneycheck/audit-ledger" {
		t.Errorf("Substrate = %q", v.Substrate)
	}
	if v.Verdict != "LIT" {
		t.Errorf("Verdict = %q, want LIT", v.Verdict)
	}
	if v.Severity != "n/a" {
		t.Errorf("Severity = %q, want n/a", v.Severity)
	}
	if v.Location != "flagships/moneycheck/audit-ledger@decide" {
		t.Errorf("Location = %q", v.Location)
	}
	if !strings.Contains(v.Evidence, "run self-check: 1 entries") {
		t.Errorf("Evidence missing entry count: %q", v.Evidence)
	}
	if !strings.Contains(v.Evidence, "ledger digest "+wantHex[:16]) {
		t.Errorf("Evidence missing digest prefix: %q", v.Evidence)
	}
	if !strings.Contains(v.Evidence, "self-check, NOT an independent gauntlet") {
		t.Errorf("Evidence missing the honesty caveat: %q", v.Evidence)
	}
	if v.OracleStrength != "Self-Check" {
		t.Errorf("OracleStrength = %q, want Self-Check", v.OracleStrength)
	}
	if v.SealedAt != "2026-06-12T12:00:00Z" {
		t.Errorf("SealedAt = %q", v.SealedAt)
	}
	if v.GauntletRun != "" {
		t.Errorf("GauntletRun = %q, want empty", v.GauntletRun)
	}
	if v.SubjectHash != wantHex {
		t.Errorf("SubjectHash = %q, want %q", v.SubjectHash, wantHex)
	}

	// Determinism: same entries (digest) → same payload.
	if v2 := NewRunAnchor("decide", 1, digest, sealedAt); v2 != v {
		t.Errorf("NewRunAnchor non-deterministic:\n a=%+v\n b=%+v", v, v2)
	}
}

// TestSealSuccess pins the wire shape: POST /v1/verdicts with the full
// JSON body, and receipt parsing from 201 + sealed{seq, entry_hash}.
func TestSealSuccess(t *testing.T) {
	digest := fixedDigest()
	want := NewRunAnchor("sar", 1, digest, time.Date(2026, 6, 12, 9, 30, 0, 0, time.UTC))

	var got Verdict
	var gotMethod, gotPath, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotCT = r.Method, r.URL.Path, r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("server decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, `{"sealed":{"seq":15,"entry_hash":"ab12cd34ef56"},"receipt":"recompute it yourself"}`)
	}))
	defer srv.Close()

	rcpt, err := NewClient(srv.URL + "/").Seal(want) // trailing slash exercises TrimRight
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/verdicts" {
		t.Errorf("request = %s %s, want POST /v1/verdicts", gotMethod, gotPath)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if got != want {
		t.Errorf("payload drift:\n sent=%+v\n want=%+v", got, want)
	}
	if rcpt.Seq != 15 || rcpt.EntryHash != "ab12cd34ef56" {
		t.Errorf("receipt = %+v, want seq=15 entry_hash=ab12cd34ef56", rcpt)
	}
}

// TestSealNon201 pins that any non-201 status surfaces as an error —
// a refused seal must never read as anchored.
func TestSealNon201(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, `{"error":"substrate and location are required"}`)
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).Seal(NewRunAnchor("decide", 1, fixedDigest(), time.Now().UTC()))
	if err == nil {
		t.Fatalf("Seal on 400 = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "status 400") {
		t.Errorf("error %q missing status code", err)
	}
}

// TestSeal201WithoutEntryHash pins the never-overclaim rule: a 201
// without sealed.entry_hash is NOT a receipt.
func TestSeal201WithoutEntryHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, `{}`)
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL).Seal(NewRunAnchor("decide", 1, fixedDigest(), time.Now().UTC()))
	if err == nil {
		t.Fatalf("Seal on 201-without-entry_hash = nil error, want refusal to claim anchored")
	}
}

// TestSealNetworkError pins that a dead spine surfaces as an error.
func TestSealNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // dead before use

	_, err := NewClient(srv.URL).Seal(NewRunAnchor("decide", 1, fixedDigest(), time.Now().UTC()))
	if err == nil {
		t.Fatalf("Seal against dead server = nil error, want failure")
	}
}

// --- HTTPS-enforcement (transport-confidentiality) pins ----------------

// TestSealRejectsNonLoopbackHTTP is the load-bearing discrimination pin:
// a non-loopback http:// spine URL anchors the run-ledger digest in
// CLEARTEXT over the network. The seal MUST fail-closed (non-nil error,
// NO HTTP request emitted) for any non-loopback http:// host. Reverting
// the HTTPS-enforcement guard makes this test fail: Seal would dial the
// plaintext host and surface a connection/transport error (or worse,
// succeed) rather than the explicit insecure-scheme refusal.
func TestSealRejectsNonLoopbackHTTP(t *testing.T) {
	for _, url := range []string{
		"http://spine.example.com",
		"http://spine.example.com:8097",
		"http://10.0.0.5:8097",            // RFC1918 — still cleartext on the wire
		"http://192.168.1.10",             // RFC1918
		"http://203.0.113.7/",             // public literal IP
		"HTTP://Spine.Example.Com:8097",   // scheme/host case-insensitivity
	} {
		_, err := NewClient(url).Seal(NewRunAnchor("decide", 1, fixedDigest(), time.Now().UTC()))
		if err == nil {
			t.Errorf("Seal(%q) = nil error, want fail-closed refusal of cleartext anchor to a non-loopback host", url)
			continue
		}
		if !strings.Contains(err.Error(), "https") {
			t.Errorf("Seal(%q) error = %q, want a message naming the https requirement", url, err)
		}
	}
}

// TestSealRejectsNonHTTPScheme pins that categorically unsafe schemes
// (file://, gopher://, etc.) and schemeless/garbage URLs are refused
// before any I/O — the anchor seam only ever speaks HTTP(S).
func TestSealRejectsNonHTTPScheme(t *testing.T) {
	for _, url := range []string{
		"file:///etc/passwd",
		"gopher://spine.example.com",
		"ftp://spine.example.com",
		"spine.example.com:8097", // no scheme → host parses as scheme; reject
	} {
		_, err := NewClient(url).Seal(NewRunAnchor("decide", 1, fixedDigest(), time.Now().UTC()))
		if err == nil {
			t.Errorf("Seal(%q) = nil error, want refusal of a non-http(s) scheme", url)
		}
	}
}

// TestSealAllowsLoopbackHTTP pins the explicit opt-out: http:// is
// allowed for loopback hosts (the documented MONEYCHECK_STELE_URL
// example is http://localhost:8097, and every httptest.NewServer binds
// to 127.0.0.1) — local dev/anchoring against a co-located spine stays
// cleartext-OK because the bytes never leave the host. This guards
// against an over-broad fix that would break the loopback workflow.
func TestSealAllowsLoopbackHTTP(t *testing.T) {
	// 127.0.0.1 (httptest default) — the existing success-path tests
	// already exercise this, re-pinned here explicitly alongside the
	// hostname form.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, `{"sealed":{"seq":7,"entry_hash":"loopbackok"}}`)
	}))
	defer srv.Close()

	rcpt, err := NewClient(srv.URL).Seal(NewRunAnchor("decide", 1, fixedDigest(), time.Now().UTC()))
	if err != nil {
		t.Fatalf("Seal against loopback http server = %v, want success (loopback http is allowed)", err)
	}
	if rcpt.EntryHash != "loopbackok" {
		t.Errorf("receipt = %+v, want entry_hash=loopbackok", rcpt)
	}

	// "localhost" hostname form must also be accepted by the scheme
	// guard (it fails later at the dial, not at the guard — so the
	// error, if any, must NOT be the https-scheme refusal).
	_, err = NewClient("http://localhost:0").Seal(NewRunAnchor("decide", 1, fixedDigest(), time.Now().UTC()))
	if err != nil && strings.Contains(err.Error(), "https") {
		t.Errorf("Seal(http://localhost:0) wrongly refused by the https guard: %v", err)
	}
}

// TestSealAllowsHTTPSAnyHost pins that https:// is accepted for any host
// — the guard's whole purpose is to permit confidential transport
// anywhere while restricting cleartext to loopback. A dial to an
// unroutable https host fails at the network layer, NOT at the scheme
// guard, so the error (if any) must not be the https refusal.
func TestSealAllowsHTTPSAnyHost(t *testing.T) {
	_, err := NewClient("https://spine.example.com:8097").Seal(NewRunAnchor("decide", 1, fixedDigest(), time.Now().UTC()))
	if err != nil && strings.Contains(err.Error(), "requires https") {
		t.Errorf("Seal(https://...) wrongly refused by the https guard: %v", err)
	}
}

// TestAnchorRunRejectsNonLoopbackHTTP pins the guard end-to-end through
// the single CLI seam: a passing self-check followed by a cleartext
// non-loopback anchor target must surface a loud error with
// anchored=false — never a silent cleartext seal.
func TestAnchorRunRejectsNonLoopbackHTTP(t *testing.T) {
	fc := &fakeChecker{entries: 1, digest: fixedDigest()}
	_, anchored, err := AnchorRun("http://spine.example.com:8097", "decide", fc, time.Now().UTC())
	if err == nil {
		t.Fatalf("AnchorRun(non-loopback http) = nil error, want fail-closed refusal")
	}
	if anchored {
		t.Errorf("anchored = true on a refused cleartext anchor")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("AnchorRun error = %q, want a message naming the https requirement", err)
	}
}

// TestAnchorRunDisabled pins the off-by-default contract: empty (or
// whitespace) URL means NO self-check, NO HTTP, no receipt, no error —
// behavior identical to a non-anchoring run.
func TestAnchorRunDisabled(t *testing.T) {
	for _, url := range []string{"", "   "} {
		fc := &fakeChecker{entries: 1, digest: fixedDigest()}
		rcpt, anchored, err := AnchorRun(url, "decide", fc, time.Now().UTC())
		if err != nil {
			t.Errorf("AnchorRun(%q) error = %v, want nil", url, err)
		}
		if anchored {
			t.Errorf("AnchorRun(%q) anchored = true, want false", url)
		}
		if rcpt != (Receipt{}) {
			t.Errorf("AnchorRun(%q) receipt = %+v, want zero", url, rcpt)
		}
		if fc.calls != 0 {
			t.Errorf("AnchorRun(%q) ran the ledger self-check %d times, want 0 (zero behavior change)", url, fc.calls)
		}
	}
}

// TestAnchorRunSelfCheckFailureSealsNothing pins the honesty gate: a
// ledger that fails its self-check seals NOTHING — zero HTTP calls.
func TestAnchorRunSelfCheckFailureSealsNothing(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, `{"sealed":{"seq":1,"entry_hash":"deadbeef"}}`)
	}))
	defer srv.Close()

	fc := &fakeChecker{err: fmt.Errorf("entry 0 mark does not re-derive")}
	_, anchored, err := AnchorRun(srv.URL, "decide", fc, time.Now().UTC())
	if err == nil {
		t.Fatalf("AnchorRun with failing self-check = nil error, want loud failure")
	}
	if anchored {
		t.Errorf("anchored = true on failed self-check")
	}
	if hits != 0 {
		t.Errorf("spine received %d requests after a failed self-check, want 0 (seal nothing)", hits)
	}
}

// TestAnchorRunSuccess pins the end-to-end seam: passing self-check →
// sealed verdict whose subject_hash is the ledger digest hex →
// receipt returned, anchored=true. Same digest → same subject_hash on
// the wire (determinism at the seam).
func TestAnchorRunSuccess(t *testing.T) {
	digest := fixedDigest()
	var subjectHashes []string
	seq := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v Verdict
		_ = json.NewDecoder(r.Body).Decode(&v)
		subjectHashes = append(subjectHashes, v.SubjectHash)
		seq++
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"sealed":{"seq":%d,"entry_hash":"hash%d"}}`, seq, seq)
	}))
	defer srv.Close()

	fc := &fakeChecker{entries: 1, digest: digest}
	rcpt, anchored, err := AnchorRun(srv.URL, "sar", fc, time.Now().UTC())
	if err != nil {
		t.Fatalf("AnchorRun: %v", err)
	}
	if !anchored {
		t.Fatalf("anchored = false on success")
	}
	if rcpt.Seq != 1 || rcpt.EntryHash != "hash1" {
		t.Errorf("receipt = %+v, want seq=1 entry_hash=hash1", rcpt)
	}
	if fc.calls != 1 {
		t.Errorf("self-check ran %d times, want 1", fc.calls)
	}

	// Second anchor of the same ledger state → identical subject_hash.
	if _, _, err := AnchorRun(srv.URL, "sar", fc, time.Now().UTC()); err != nil {
		t.Fatalf("AnchorRun second: %v", err)
	}
	wantHex := hex.EncodeToString(digest[:])
	if len(subjectHashes) != 2 || subjectHashes[0] != wantHex || subjectHashes[1] != wantHex {
		t.Errorf("subject_hashes = %v, want both %q (deterministic binding)", subjectHashes, wantHex)
	}
}
