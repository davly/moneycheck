// Package audit_ledger — append-only audit ledger with production-
// wired Mirror-Mark v1 stamping for moneycheck.
//
// 2026-05-27 new-flagship-inception ship. Pure-stdlib; zero deps.
//
// **R175 production-wired Mirror-Mark FROM INCEPTION**: every Emit()
// call stamps the entry with a Mirror-Mark v1 HMAC over the canonical
// body (with mark cleared). A downstream FCA / NCA inspector holding
// (lore.tar.gz, entry bytes with mark cleared, the PSP's iik_ key)
// can re-derive the mark via internal/mirrormark.Verify and confirm
// the PSP emitted exactly these bytes.
//
// Phase 1 audit-ledger emits to an in-memory sink only; no payment-
// rail integration, no NCA submission, no FCA filing. The Mirror-Mark
// stamping is the load-bearing artefact regardless of where the ledger
// is persisted — a future Phase host PSP integration will wire the
// in-memory sink to a real Bolt / Postgres / cloud audit-ledger
// without changing the entry-bytes or the mark format.
//
// R7 fire-and-forget: Emit() is synchronous + fast (HMAC-SHA256 over
// a JSON body); no network calls, no blocking. Phase 1 in-memory sink
// is goroutine-safe via sync.Mutex.
//
// Cross-substrate parity: the canonical entry-body JSON shape is
// byte-aligned with the cohort canonical (casino + ledger + insights)
// audit-ledger entry format. A regulator's cold-verify CLI tools the
// same entry across the cohort.
package audit_ledger

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/davly/moneycheck/internal/mirrormark"
)

// EntryClass is the closed-set audit-entry classification. NOT
// free-form; downstream tooling branches on this discriminator.
type EntryClass string

const (
	// EntryClassPSRDisposition — a PSR APP-fraud reimbursement
	// disposition was emitted (Reimburse / Deny / EscapeToHuman /
	// Placeholder).
	EntryClassPSRDisposition EntryClass = "psr.app-fraud.disposition"

	// EntryClassSARFiling — a SAR candidate was processed (Phase 1
	// placeholder; Phase 3 envelope).
	EntryClassSARFiling EntryClass = "aml.sar.filing"

	// EntryClassSCAEscape — the SCA escape gate fired (R153 saturator).
	EntryClassSCAEscape EntryClass = "psd2.sca.escape"

	// EntryClassDisclosure — an FCA COBS 4 customer disclosure was
	// rendered (Phase 4).
	EntryClassDisclosure EntryClass = "fca.cobs4.disclosure"

	// EntryClassAdvisoryFired — a moneycheck R143 advisory fired
	// (operational visibility).
	EntryClassAdvisoryFired EntryClass = "advisory.r143"
)

// Entry is the canonical audit-ledger entry shape. Field order is
// byte-significant for the Mirror-Mark canonical body (JSON marshal
// determinism is bedded in encoding/json field order = struct field
// order).
type Entry struct {
	// EntryID is the PSP-internal ledger sequence number.
	EntryID string `json:"entry_id"`

	// Class is the closed-set entry classification.
	Class EntryClass `json:"class"`

	// Timestamp is the wall-clock UTC time the entry was emitted.
	// RFC3339 millisecond-precision string.
	Timestamp string `json:"timestamp"`

	// Reference is the cross-reference into the originating domain
	// surface (e.g. claim ID, SAR candidate ID, disclosure form ID).
	Reference string `json:"reference"`

	// Payload is the entry-class-specific body. JSON marshalled as
	// part of the canonical Mirror-Mark input.
	Payload json.RawMessage `json:"payload"`

	// AdvisoryCodes lists the R143 LOUD-ONCE-WARN advisory codes
	// associated with this entry (echoed from the originating
	// domain surface).
	AdvisoryCodes []string `json:"advisory_codes,omitempty"`

	// MirrorMark is the L43 Mirror-Mark v1 signature computed over
	// the canonical body (this struct with MirrorMark = ""). Stamped
	// by Emit() FROM INCEPTION (R175 criterion 1: production-traffic
	// emit-path).
	//
	// json `omitempty` is intentional but the canonical body MUST
	// include the empty `mirror_mark` field for cold-verify recompute
	// to match — see Emit() for the clear-then-marshal-then-stamp
	// discipline.
	MirrorMark string `json:"mirror_mark,omitempty"`
}

// Ledger is the in-memory append-only audit ledger. Phase 1 scope;
// Phase 2 wires a Bolt / Postgres persistent sink behind the same
// interface. Goroutine-safe.
//
// R175 production-wired: every Emit() stamps the entry with a
// Mirror-Mark v1 HMAC. The marker is set at Ledger construction; if
// nil, Ledger emits unsigned entries (the LOUD-ONCE-WARN advisory
// fires in honest/ when the marker is missing).
type Ledger struct {
	mu      sync.Mutex
	entries []Entry
	marker  mirrormark.Marker
	nextID  int
}

// NewLedger constructs an in-memory Ledger wired to the given
// Mirror-Mark marker. If marker is nil, NewLedgerWithMarker still
// returns a ledger but Emit() will skip the stamping step (and the
// downstream regulator cold-verify will fail honestly).
//
// R175 4-criteria from inception: production callers MUST construct
// the Ledger with a real (non-placeholder) marker for the cold-verify
// path to hold.
func NewLedger(marker mirrormark.Marker) *Ledger {
	return &Ledger{
		marker:  marker,
		entries: nil,
		nextID:  1,
	}
}

// Emit appends an entry to the ledger. R175 production-wired: the
// entry is stamped with a Mirror-Mark v1 HMAC over the canonical body
// (with MirrorMark cleared) before being appended.
//
// The clear-then-marshal-then-stamp discipline mirrors the casino +
// ledger + insights cohort canonical pattern: a regulator clearing
// MirrorMark and re-marshalling reproduces the HMAC input bytes
// exactly.
//
// If the Ledger's marker is nil, Emit appends the entry with empty
// MirrorMark (honest signal of unsigned operation). The R143
// LOUD-ONCE-WARN advisory MUST be surfaced separately at the call
// site.
//
// Returns the appended entry (with MirrorMark populated) so the
// caller can echo the mark into downstream artefacts (HTTP response,
// SAR-filing receipt, etc).
func (l *Ledger) Emit(entry Entry) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Auto-assign EntryID if absent.
	if entry.EntryID == "" {
		entry.EntryID = formatEntryID(l.nextID)
		l.nextID++
	}

	// Auto-set timestamp if absent.
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}

	// R175 stamp: clear MirrorMark, marshal canonical body, sign,
	// stamp.
	entry.MirrorMark = ""
	if l.marker != nil {
		body, err := json.Marshal(entry)
		if err == nil {
			entry.MirrorMark = l.marker.Sign(body)
		}
		// On marshal err, MirrorMark stays empty — the downstream
		// regulator sees "unsigned entry" (honest signal of internal
		// failure), not a crashing emit path. R7 fire-and-forget.
	}

	l.entries = append(l.entries, entry)
	return entry
}

// Entries returns a defensive copy of the appended entries.
func (l *Ledger) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Count returns the number of appended entries.
func (l *Ledger) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// VerifyEntry re-derives a Mirror-Mark over the entry's canonical
// body (with MirrorMark cleared) and compares against the carried
// MirrorMark. Returns nil iff the mark matches.
//
// Cold-verify contract: a regulator holding (corpusSHA, the entry
// bytes with MirrorMark cleared, the PSP's iik_ key) re-derives the
// mark via internal/mirrormark.Verify and confirms the PSP emitted
// exactly these bytes.
func VerifyEntry(entry Entry, marker mirrormark.Marker) error {
	if marker == nil {
		return mirrormark.ErrMarkerNotConfigured
	}
	// Stash + clear the mark for canonical body re-derivation.
	mark := entry.MirrorMark
	entry.MirrorMark = ""
	body, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	// Re-sign with marker; the result MUST equal the stashed mark.
	want := marker.Sign(body)
	if want != mark {
		return mirrormark.ErrMarkMismatch
	}
	return nil
}

// formatEntryID returns the canonical sequence-number entry ID.
// Pinned format for cross-substrate cohort parity: "MC-<8-digit-seq>".
func formatEntryID(n int) string {
	const padded = "00000000"
	s := intToString(n)
	if len(s) >= len(padded) {
		return "MC-" + s
	}
	return "MC-" + padded[:len(padded)-len(s)] + s
}

// intToString is a stdlib-only int → decimal-string converter
// (avoids strconv import to keep dependency surface minimal —
// audit_ledger has no other strconv use today).
func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + intToString(-n)
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + (n % 10))
		n /= 10
	}
	return string(buf[i:])
}
