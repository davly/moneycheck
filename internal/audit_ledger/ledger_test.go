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
