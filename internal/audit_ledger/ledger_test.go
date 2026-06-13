package audit_ledger

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/davly/moneycheck/internal/mirrormark"
)

// TestEntryClassLiteralsPinned pins the cohort-canonical entry-class
// string literals.
func TestEntryClassLiteralsPinned(t *testing.T) {
	pairs := map[EntryClass]string{
		EntryClassPSRDisposition: "psr.app-fraud.disposition",
		EntryClassSARFiling:      "aml.sar.filing",
		EntryClassSCAEscape:      "psd2.sca.escape",
		EntryClassDisclosure:     "fca.cobs4.disclosure",
		EntryClassAdvisoryFired:  "advisory.r143",
	}
	for got, want := range pairs {
		if string(got) != want {
			t.Errorf("EntryClass literal = %q, want %q", got, want)
		}
	}
}

// TestEmit_R175_StampedFromInception pins the R175 production-wired
// criterion: every Emit() call stamps the entry with a Mirror-Mark.
func TestEmit_R175_StampedFromInception(t *testing.T) {
	var corpus [sha256.Size]byte
	corpus[0] = 0x42
	marker, err := mirrormark.NewStdlibMarker(corpus, []byte("test-key-32-bytes-exactly--------"))
	if err != nil {
		t.Fatalf("NewStdlibMarker: %v", err)
	}

	ledger := NewLedger(marker)
	payload, _ := json.Marshal(map[string]string{"foo": "bar"})
	entry := Entry{
		Class:     EntryClassPSRDisposition,
		Reference: "claim-001",
		Payload:   payload,
	}
	emitted := ledger.Emit(entry)

	if emitted.MirrorMark == "" {
		t.Error("R175 violation: Emit() returned entry with empty MirrorMark")
	}
	if !strings.HasPrefix(emitted.MirrorMark, "lore@v1:") {
		t.Errorf("MirrorMark = %q, want \"lore@v1:\" prefix", emitted.MirrorMark)
	}
}

// TestEmit_AutoAssignsEntryID pins the entry-ID auto-assignment
// behaviour.
func TestEmit_AutoAssignsEntryID(t *testing.T) {
	ledger := NewLedger(nil)
	e1 := ledger.Emit(Entry{Class: EntryClassPSRDisposition})
	e2 := ledger.Emit(Entry{Class: EntryClassSARFiling})

	if e1.EntryID != "MC-00000001" {
		t.Errorf("first auto-assigned EntryID = %q, want %q", e1.EntryID, "MC-00000001")
	}
	if e2.EntryID != "MC-00000002" {
		t.Errorf("second auto-assigned EntryID = %q, want %q", e2.EntryID, "MC-00000002")
	}
}

// TestEmit_NilMarkerEmitsUnsigned pins the honest-failure mode: a
// nil marker still allows Emit() to succeed (R7 fire-and-forget) but
// the entry has empty MirrorMark.
func TestEmit_NilMarkerEmitsUnsigned(t *testing.T) {
	ledger := NewLedger(nil)
	entry := ledger.Emit(Entry{Class: EntryClassAdvisoryFired, Reference: "test"})
	if entry.MirrorMark != "" {
		t.Errorf("nil-marker Emit() should have empty MirrorMark, got %q", entry.MirrorMark)
	}
}

// TestEmit_AppendsToLedger pins the append-only behaviour.
func TestEmit_AppendsToLedger(t *testing.T) {
	ledger := NewLedger(nil)
	_ = ledger.Emit(Entry{Class: EntryClassPSRDisposition})
	_ = ledger.Emit(Entry{Class: EntryClassSARFiling})
	_ = ledger.Emit(Entry{Class: EntryClassSCAEscape})

	if got := ledger.Count(); got != 3 {
		t.Errorf("Count() = %d, want 3", got)
	}
	entries := ledger.Entries()
	if len(entries) != 3 {
		t.Errorf("Entries() length = %d, want 3", len(entries))
	}
}

// TestVerifyEntry_RoundTrip pins the cold-verify contract: an emitted
// entry verifies under the same marker.
func TestVerifyEntry_RoundTrip(t *testing.T) {
	var corpus [sha256.Size]byte
	corpus[0] = 0x99
	marker, err := mirrormark.NewStdlibMarker(corpus, []byte("regulator-cold-verify-key-32-byt"))
	if err != nil {
		t.Fatalf("NewStdlibMarker: %v", err)
	}

	ledger := NewLedger(marker)
	emitted := ledger.Emit(Entry{
		Class:     EntryClassPSRDisposition,
		Reference: "claim-roundtrip",
		Payload:   json.RawMessage(`{"disposition":"placeholder"}`),
	})

	if err := VerifyEntry(emitted, marker); err != nil {
		t.Errorf("VerifyEntry(emitted) = %v, want nil", err)
	}

	// Tamper detection: modify the payload, verify must fail.
	tampered := emitted
	tampered.Payload = json.RawMessage(`{"disposition":"reimburse"}`)
	if err := VerifyEntry(tampered, marker); err != mirrormark.ErrMarkMismatch {
		t.Errorf("VerifyEntry(tampered) = %v, want ErrMarkMismatch", err)
	}
}

// TestVerifyEntry_NilMarkerRefuses pins the regulator-side refusal of
// nil-marker verification.
func TestVerifyEntry_NilMarkerRefuses(t *testing.T) {
	emitted := Entry{
		Class:      EntryClassPSRDisposition,
		MirrorMark: "lore@v1:nonsense",
	}
	if err := VerifyEntry(emitted, nil); err != mirrormark.ErrMarkerNotConfigured {
		t.Errorf("VerifyEntry(nil marker) = %v, want ErrMarkerNotConfigured", err)
	}
}

// TestEmit_R175_StampUsesClearedMirrorMarkInput pins the canonical
// clear-then-marshal-then-stamp discipline: the HMAC input is the
// JSON body with MirrorMark cleared. A regulator clearing MirrorMark
// + re-marshalling reproduces the input.
func TestEmit_R175_StampUsesClearedMirrorMarkInput(t *testing.T) {
	var corpus [sha256.Size]byte
	corpus[5] = 0x77
	marker, _ := mirrormark.NewStdlibMarker(corpus, []byte("test-key-canonical-body----------"))

	ledger := NewLedger(marker)
	emitted := ledger.Emit(Entry{
		Class:     EntryClassSARFiling,
		Reference: "sar-canonical",
		Payload:   json.RawMessage(`{"grounds":"layering_indicator"}`),
	})

	// Independently re-derive the mark: clear MirrorMark, marshal,
	// sign with the same marker.
	canonical := emitted
	canonical.MirrorMark = ""
	body, err := json.Marshal(canonical)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wantMark := marker.Sign(body)
	if emitted.MirrorMark != wantMark {
		t.Errorf("R175 canonical-body re-derivation mismatch:\nemitted = %q\nrederived = %q", emitted.MirrorMark, wantMark)
	}
}

// newTestMarkerLedger builds a ledger backed by a deterministic
// production-style marker (non-placeholder) so SelfCheck can verify
// real marks.
func newTestMarkerLedger(t *testing.T) *Ledger {
	t.Helper()
	var corpus [sha256.Size]byte
	corpus[0] = 0xAB
	marker, err := mirrormark.NewStdlibMarker(corpus, []byte("selfcheck-test-key-32-bytes-long"))
	if err != nil {
		t.Fatalf("NewStdlibMarker: %v", err)
	}
	return NewLedger(marker)
}

// TestSelfCheck_PassDeterministic pins that SelfCheck over a clean
// ledger returns the entry count + a deterministic digest, and that
// the digest matches the documented canonical serialization
// (sha256 over json.Marshal(entry) || '\n' per stamped entry in
// append order).
func TestSelfCheck_PassDeterministic(t *testing.T) {
	ledger := newTestMarkerLedger(t)
	// Pin entry IDs + timestamps so the digest is reproducible.
	for i, ref := range []string{"claim-A", "claim-B"} {
		ledger.entries = append(ledger.entries, mustStamp(t, ledger, Entry{
			EntryID:   formatEntryID(i + 1),
			Class:     EntryClassPSRDisposition,
			Timestamp: "2026-06-12T00:00:00.000Z",
			Reference: ref,
			Payload:   json.RawMessage(`{"disposition":"placeholder"}`),
		}))
	}

	n, digest, err := ledger.SelfCheck()
	if err != nil {
		t.Fatalf("SelfCheck() = %v, want nil", err)
	}
	if n != 2 {
		t.Errorf("SelfCheck entry count = %d, want 2", n)
	}

	// Independently re-derive the documented digest.
	h := sha256.New()
	for _, e := range ledger.Entries() {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		h.Write(line)
		h.Write([]byte{'\n'})
	}
	var want [sha256.Size]byte
	copy(want[:], h.Sum(nil))
	if digest != want {
		t.Errorf("digest = %x, want %x (documented canonical serialization)", digest, want)
	}

	// Determinism: a second self-check of the same state → same digest.
	_, digest2, err := ledger.SelfCheck()
	if err != nil || digest2 != digest {
		t.Errorf("SelfCheck non-deterministic: digest2=%x err=%v", digest2, err)
	}
}

// mustStamp emits an entry through the ledger's marker without going
// through the public auto-ID/auto-timestamp path, so a test can pin
// exact entry bytes (EntryID + Timestamp pre-set). It mirrors Emit's
// clear-then-marshal-then-stamp discipline.
func mustStamp(t *testing.T, l *Ledger, e Entry) Entry {
	t.Helper()
	e.MirrorMark = ""
	body, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("mustStamp marshal: %v", err)
	}
	e.MirrorMark = l.marker.Sign(body)
	return e
}

// TestSelfCheck_TamperDetected pins the integrity gate: mutating an
// entry's payload after stamping breaks SelfCheck (mark no longer
// re-derives) and yields a zero digest.
func TestSelfCheck_TamperDetected(t *testing.T) {
	ledger := newTestMarkerLedger(t)
	ledger.Emit(Entry{Class: EntryClassPSRDisposition, Reference: "ok", Payload: json.RawMessage(`{"v":1}`)})

	// Clean self-check first.
	if _, _, err := ledger.SelfCheck(); err != nil {
		t.Fatalf("clean SelfCheck = %v, want nil", err)
	}

	// Tamper with the in-memory entry payload (mark stays stale).
	ledger.entries[0].Payload = json.RawMessage(`{"v":2}`)

	n, digest, err := ledger.SelfCheck()
	if err == nil {
		t.Fatalf("SelfCheck on tampered entry = nil error, want mismatch")
	}
	if n != 0 || digest != ([sha256.Size]byte{}) {
		t.Errorf("tampered SelfCheck = (%d, %x), want (0, zero-digest)", n, digest)
	}
}

// TestSelfCheck_MissingPrefixRejected pins that an entry whose mark
// lacks the cohort-canonical "lore@v1:" prefix (e.g. an unsigned
// nil-marker emit smuggled in) fails self-check.
func TestSelfCheck_MissingPrefixRejected(t *testing.T) {
	ledger := newTestMarkerLedger(t)
	ledger.entries = append(ledger.entries, Entry{
		EntryID:    "MC-00000001",
		Class:      EntryClassPSRDisposition,
		Timestamp:  "2026-06-12T00:00:00.000Z",
		MirrorMark: "", // missing prefix
	})
	if _, _, err := ledger.SelfCheck(); err == nil {
		t.Fatalf("SelfCheck on prefix-less entry = nil error, want failure")
	}
}

// TestSelfCheck_NilMarkerRefuses pins that a ledger with no marker
// configured cannot self-check green (an unsigned ledger must never be
// anchored LIT).
func TestSelfCheck_NilMarkerRefuses(t *testing.T) {
	ledger := NewLedger(nil)
	ledger.Emit(Entry{Class: EntryClassAdvisoryFired, Reference: "unsigned"})
	if _, _, err := ledger.SelfCheck(); err == nil {
		t.Fatalf("SelfCheck on nil-marker ledger = nil error, want refusal")
	}
}

// TestSelfCheck_EmptyLedger pins that an empty ledger self-checks green
// with a stable digest (sha256 of the empty stream).
func TestSelfCheck_EmptyLedger(t *testing.T) {
	ledger := newTestMarkerLedger(t)
	n, digest, err := ledger.SelfCheck()
	if err != nil {
		t.Fatalf("empty SelfCheck = %v, want nil", err)
	}
	if n != 0 {
		t.Errorf("empty SelfCheck count = %d, want 0", n)
	}
	var wantEmpty [sha256.Size]byte
	copy(wantEmpty[:], sha256.New().Sum(nil))
	if digest != wantEmpty {
		t.Errorf("empty-ledger digest = %x, want sha256-of-empty %x", digest, wantEmpty)
	}
}

// TestEmit_GoroutineSafe ensures concurrent Emit calls do not corrupt
// the ledger state. Pin the mutex contract.
func TestEmit_GoroutineSafe(t *testing.T) {
	ledger := NewLedger(nil)
	const n = 100
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func() {
			_ = ledger.Emit(Entry{Class: EntryClassAdvisoryFired})
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}
	if got := ledger.Count(); got != n {
		t.Errorf("concurrent Count() = %d, want %d", got, n)
	}
}
