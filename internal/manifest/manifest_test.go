package manifest

import (
	"testing"
	"time"
)

// TestSchemaVersionPinnedAtV1 pins the cohort-canonical R150 schema
// version. Bumping invalidates every entry.
func TestSchemaVersionPinnedAtV1(t *testing.T) {
	if SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1 (cohort canonical R150)", SchemaVersion)
	}
}

// TestSentinelHonestTODOPinned pins the canonical zero-time sentinel
// (1970-01-01 UTC per godfather R150 canonical shape).
func TestSentinelHonestTODOPinned(t *testing.T) {
	want := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	if !SentinelHonestTODO.Equal(want) {
		t.Errorf("SentinelHonestTODO = %v, want %v (cohort canonical R150)", SentinelHonestTODO, want)
	}
}

// TestSourceClosedSet pins the closed Source enum at the expected
// cardinality. Adding/removing a Source value is a behavior-changing
// event per R145.B.
func TestSourceClosedSet(t *testing.T) {
	pairs := []struct {
		s    Source
		name string
	}{
		{SourceUnknownHonestTODO, "unknown_honest_todo"},
		{SourceUKPrimaryLegislation, "uk_primary_legislation"},
		{SourceUKStatutoryInstrument, "uk_statutory_instrument"},
		{SourceFCARulebook, "fca_rulebook"},
		{SourceEUDelegatedRegulation, "eu_delegated_regulation"},
		{SourceNCAGuidance, "nca_guidance"},
		{SourceCounselReview, "counsel_review"},
		{SourcePhasePending, "phase_pending"},
	}
	for i, p := range pairs {
		if int(p.s) != i {
			t.Errorf("Source %q ordinal = %d, want %d (re-order detected)", p.name, int(p.s), i)
		}
		if got := p.s.String(); got != p.name {
			t.Errorf("Source(%d).String() = %q, want %q", p.s, got, p.name)
		}
	}
}

// TestConfidenceClosedSet pins the closed 3-state Confidence enum.
func TestConfidenceClosedSet(t *testing.T) {
	pairs := []struct {
		c    Confidence
		name string
	}{
		{ConfidenceHonestTODO, "honest_todo"},
		{ConfidenceMedium, "medium"},
		{ConfidenceHigh, "high"},
	}
	for i, p := range pairs {
		if int(p.c) != i {
			t.Errorf("Confidence %q ordinal = %d, want %d", p.name, int(p.c), i)
		}
		if got := p.c.String(); got != p.name {
			t.Errorf("Confidence(%d).String() = %q, want %q", p.c, got, p.name)
		}
	}
}

// TestClassClosedSet pins the closed 4-state Class enum.
func TestClassClosedSet(t *testing.T) {
	pairs := []struct {
		cl   Class
		name string
	}{
		{ClassRegRegime, "reg_regime"},
		{ClassSARFilingChannel, "sar_filing_channel"},
		{ClassSCAExemption, "sca_exemption"},
		{ClassCounselReview, "counsel_review"},
	}
	for i, p := range pairs {
		if int(p.cl) != i {
			t.Errorf("Class %q ordinal = %d, want %d", p.name, int(p.cl), i)
		}
		if got := p.cl.String(); got != p.name {
			t.Errorf("Class(%d).String() = %q, want %q", p.cl, got, p.name)
		}
	}
}

// Test_IsStale_NinePaths exercises the 9-path R150 canonical IsStale
// contract.
func Test_IsStale_NinePaths(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)

	// Path 1: SourceUnknownHonestTODO → true
	e := Entry{Source: SourceUnknownHonestTODO, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: now}
	if !e.IsStale(now, 0) {
		t.Error("path 1: SourceUnknownHonestTODO should be stale")
	}

	// Path 2: ConfidenceHonestTODO → true
	e = Entry{Source: SourceUKStatutoryInstrument, Confidence: ConfidenceHonestTODO, SchemaVersion: SchemaVersion, FreshAt: now}
	if !e.IsStale(now, 0) {
		t.Error("path 2: ConfidenceHonestTODO should be stale")
	}

	// Path 3: SchemaVersion drift → true
	e = Entry{Source: SourceUKStatutoryInstrument, Confidence: ConfidenceHigh, SchemaVersion: 999, FreshAt: now}
	if !e.IsStale(now, 0) {
		t.Error("path 3: SchemaVersion drift should be stale")
	}

	// Path 4: FreshAt == SentinelHonestTODO → true
	e = Entry{Source: SourceUKStatutoryInstrument, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: SentinelHonestTODO}
	if !e.IsStale(now, 0) {
		t.Error("path 4: SentinelHonestTODO should be stale")
	}

	// Path 5: maxAge <= 0 + above don't fire → false
	e = Entry{Source: SourceUKStatutoryInstrument, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: now}
	if e.IsStale(now, 0) {
		t.Error("path 5: fresh entry with maxAge=0 should NOT be stale")
	}

	// Path 6: FreshAt is zero-time → true
	e = Entry{Source: SourceUKStatutoryInstrument, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: time.Time{}}
	if !e.IsStale(now, 0) {
		t.Error("path 6: zero-time FreshAt should be stale")
	}

	// Path 7: FreshAt in future → true
	future := now.Add(24 * time.Hour)
	e = Entry{Source: SourceUKStatutoryInstrument, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: future}
	if !e.IsStale(now, 0) {
		t.Error("path 7: future FreshAt should be stale")
	}

	// Path 8: now.Sub(FreshAt) > maxAge → true
	old := now.Add(-30 * 24 * time.Hour)
	e = Entry{Source: SourceUKStatutoryInstrument, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: old}
	if !e.IsStale(now, 24*time.Hour) {
		t.Error("path 8: age-exceeded entry should be stale")
	}

	// Path 9: all clauses pass → false
	e = Entry{Source: SourceUKStatutoryInstrument, Confidence: ConfidenceHigh, SchemaVersion: SchemaVersion, FreshAt: now}
	if e.IsStale(now, time.Hour) {
		t.Error("path 9: fully fresh entry should NOT be stale")
	}
}

// TestSeedShape pins the canonical 13-entry inventory shape.
func TestSeedShape(t *testing.T) {
	m := Seed()
	if len(m) != 13 {
		t.Errorf("Seed() length = %d, want 13 (5 RegRegime + 3 SARFilingChannel + 4 SCAExemption + 1 CounselReview)", len(m))
	}

	// Per-class counts.
	classes := map[Class]int{}
	for _, e := range m {
		classes[e.Class]++
	}
	wantClasses := map[Class]int{
		ClassRegRegime:        5,
		ClassSARFilingChannel: 3,
		ClassSCAExemption:     4,
		ClassCounselReview:    1,
	}
	for cl, want := range wantClasses {
		if classes[cl] != want {
			t.Errorf("Class %s count = %d, want %d", cl.String(), classes[cl], want)
		}
	}
}

// TestSeedKeysCanonical pins the canonical entry keys.
func TestSeedKeysCanonical(t *testing.T) {
	m := Seed()
	wantKeys := []string{
		"PSR_2017",
		"PSR_2024_AMENDMENT",
		"POCA_330",
		"FCA_COBS_4",
		"PSD2_SCA_RTS",
		"NCA_SAR_ONLINE",
		"NCA_BULK_REPORT",
		"FCA_CONNECT_FORM",
		"SCA_LOW_VALUE",
		"SCA_TRUSTED_BENEFICIARY",
		"SCA_RECURRING",
		"SCA_CORPORATE",
		"PHASE_1_COUNSEL_REVIEW_PENDING",
	}
	if len(m) != len(wantKeys) {
		t.Fatalf("Seed length = %d, want %d", len(m), len(wantKeys))
	}
	for i, want := range wantKeys {
		if m[i].Key != want {
			t.Errorf("Seed()[%d].Key = %q, want %q", i, m[i].Key, want)
		}
	}
}

// TestSeedPhase1CounselReviewedZero pins the Phase 1 expectation that
// NO entries carry ReviewedByCounsel=true. R166 LIABILITY-FOOTER-CONST
// sibling.
func TestSeedPhase1CounselReviewedZero(t *testing.T) {
	m := Seed()
	if got := m.CounselReviewedCount(); got != 0 {
		t.Errorf("Phase 1 CounselReviewedCount = %d, want 0 (R166 sibling)", got)
	}
}

// TestFindByKey pins the (Class, Key) composite-key lookup.
func TestFindByKey(t *testing.T) {
	m := Seed()
	e := m.FindByKey(ClassRegRegime, "PSR_2017")
	if e == nil {
		t.Fatal("FindByKey(RegRegime, PSR_2017) returned nil, want entry")
	}
	if e.Key != "PSR_2017" {
		t.Errorf("FindByKey returned wrong key %q", e.Key)
	}
	if got := m.FindByKey(ClassRegRegime, "DOES_NOT_EXIST"); got != nil {
		t.Errorf("FindByKey(non-existent) = %+v, want nil", got)
	}
}

// TestHonestTODOCount pins the Phase 1 honest-TODO count (the counsel-
// review entry has both SourcePhasePending + ConfidenceHonestTODO so
// is counted).
func TestHonestTODOCount(t *testing.T) {
	m := Seed()
	got := m.HonestTODOCount()
	// The PHASE_1_COUNSEL_REVIEW_PENDING entry has ConfidenceHonestTODO
	// so qualifies. Everything else is concrete.
	if got != 1 {
		t.Errorf("HonestTODOCount = %d, want 1 (only PHASE_1_COUNSEL_REVIEW_PENDING)", got)
	}
}
