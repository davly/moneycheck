package honest

import (
	"bytes"
	"strings"
	"testing"
)

// TestLoudOncePrefixLiteral pins the cohort-canonical
// "[LOUD-ONCE-WARNING]" prefix. Drift breaks the cohort grep contract.
func TestLoudOncePrefixLiteral(t *testing.T) {
	if LoudOncePrefix != "[LOUD-ONCE-WARNING]" {
		t.Errorf("LoudOncePrefix = %q, want \"[LOUD-ONCE-WARNING]\"", LoudOncePrefix)
	}
}

// TestSeverityClosedSet pins the closed R143.A 3-tier severity ladder.
func TestSeverityClosedSet(t *testing.T) {
	pairs := []struct {
		s    Severity
		name string
	}{
		{SeverityInfo, "info"},
		{SeverityWarn, "warn"},
		{SeverityError, "error"},
	}
	for i, p := range pairs {
		if int(p.s) != i {
			t.Errorf("Severity %q ordinal = %d, want %d", p.name, int(p.s), i)
		}
		if got := p.s.String(); got != p.name {
			t.Errorf("Severity(%d).String() = %q, want %q", p.s, got, p.name)
		}
	}
}

// TestCanonicalAdvisoryCodes pins the 5 brief-specified advisory codes
// + their severities + their order. The brief lists them as: PSR-not-
// reviewed (Error) + AML-SAR-placeholder (Error) + FCA-CRD4-disclosure
// (Warn) + PSD2-SCA-escape (Error) + ReviewedByCounsel-false (Warn).
func TestCanonicalAdvisoryCodes(t *testing.T) {
	want := []struct {
		code string
		sev  Severity
	}{
		{"MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED", SeverityError},
		{"MONEYCHECK_AML_SAR_FILING_PLACEHOLDER", SeverityError},
		{"MONEYCHECK_FCA_CRD_4_DISCLOSURE_REQUIRED", SeverityWarn},
		{"MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT", SeverityError},
		{"MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE", SeverityWarn},
	}
	got := CanonicalAdvisories()
	if len(got) != len(want) {
		t.Fatalf("CanonicalAdvisories() length = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Code != w.code {
			t.Errorf("CanonicalAdvisories()[%d].Code = %q, want %q", i, got[i].Code, w.code)
		}
		if got[i].Severity != w.sev {
			t.Errorf("CanonicalAdvisories()[%d].Severity = %v, want %v", i, got[i].Severity, w.sev)
		}
		if got[i].Message == "" {
			t.Errorf("CanonicalAdvisories()[%d].Message is empty", i)
		}
		if got[i].DocLink == "" {
			t.Errorf("CanonicalAdvisories()[%d].DocLink is empty", i)
		}
	}
}

// TestSeverityLadderInventory pins the brief-specified severity
// inventory: 3 Error + 2 Warn + 0 Info.
func TestSeverityLadderInventory(t *testing.T) {
	counts := map[Severity]int{}
	for _, a := range CanonicalAdvisories() {
		counts[a.Severity]++
	}
	if counts[SeverityError] != 3 {
		t.Errorf("Error count = %d, want 3 (PSR + AML + SCA)", counts[SeverityError])
	}
	if counts[SeverityWarn] != 2 {
		t.Errorf("Warn count = %d, want 2 (FCA-CRD4 + ReviewedByCounsel)", counts[SeverityWarn])
	}
	if counts[SeverityInfo] != 0 {
		t.Errorf("Info count = %d, want 0 (Phase 1 brief shape)", counts[SeverityInfo])
	}
}

// TestLoudOnceFiresExactlyOnce pins the cohort R143 cardinality
// contract: each Code emits exactly ONCE per process.
func TestLoudOnceFiresExactlyOnce(t *testing.T) {
	Reset() // clean slate
	defer Reset()

	adv := Advisory{
		Code:     "TEST_FIRES_EXACTLY_ONCE",
		Severity: SeverityWarn,
		Message:  "test",
		DocLink:  "test.md",
	}

	var buf bytes.Buffer
	if !LoudOnce(adv, &buf) {
		t.Error("first LoudOnce returned false, want true")
	}
	if !strings.Contains(buf.String(), "TEST_FIRES_EXACTLY_ONCE") {
		t.Errorf("first LoudOnce did not write to buffer: %q", buf.String())
	}

	// Second call must NOT emit (loud-once).
	var buf2 bytes.Buffer
	if LoudOnce(adv, &buf2) {
		t.Error("second LoudOnce returned true, want false (loud-once)")
	}
	if buf2.Len() != 0 {
		t.Errorf("second LoudOnce wrote to buffer: %q", buf2.String())
	}
}

// TestLoudOnceDistinctCodesEmitIndependently pins that two different
// Codes both fire on first call.
func TestLoudOnceDistinctCodesEmitIndependently(t *testing.T) {
	Reset()
	defer Reset()

	adv1 := Advisory{Code: "CODE_ONE", Severity: SeverityInfo, Message: "a", DocLink: "x"}
	adv2 := Advisory{Code: "CODE_TWO", Severity: SeverityInfo, Message: "b", DocLink: "y"}

	var buf bytes.Buffer
	if !LoudOnce(adv1, &buf) || !LoudOnce(adv2, &buf) {
		t.Error("distinct codes did not both fire on first call")
	}
}

// TestLoudOnceEmptyCodeRefused pins that empty Code is refused (grep
// contract).
func TestLoudOnceEmptyCodeRefused(t *testing.T) {
	Reset()
	defer Reset()

	adv := Advisory{Code: "", Severity: SeverityInfo, Message: "x", DocLink: "x"}
	var buf bytes.Buffer
	if LoudOnce(adv, &buf) {
		t.Error("LoudOnce(empty code) returned true, want false")
	}
	if buf.Len() != 0 {
		t.Errorf("LoudOnce(empty code) wrote to buffer: %q", buf.String())
	}
}

// TestAdvisoryStringFormat pins the canonical advisory String() shape.
func TestAdvisoryStringFormat(t *testing.T) {
	adv := Advisory{
		Code:     "TEST_FORMAT",
		Severity: SeverityError,
		Message:  "halt",
		DocLink:  "ARCHITECTURE.md",
	}
	got := adv.String()
	wantSubstrs := []string{
		"[LOUD-ONCE-WARNING]",
		"moneycheck:",
		"TEST_FORMAT",
		"(error)",
		"halt",
		"ARCHITECTURE.md",
	}
	for _, sub := range wantSubstrs {
		if !strings.Contains(got, sub) {
			t.Errorf("Advisory.String() = %q, want substring %q", got, sub)
		}
	}
}

// TestFindByCode pins the canonical Advisory lookup-by-code surface.
func TestFindByCode(t *testing.T) {
	adv := FindByCode(CodePSRAppFraudReimbursementNotReviewed)
	if adv == nil {
		t.Fatal("FindByCode(PSR) returned nil, want canonical advisory")
	}
	if adv.Severity != SeverityError {
		t.Errorf("PSR severity = %v, want Error", adv.Severity)
	}
	if got := FindByCode("DOES_NOT_EXIST"); got != nil {
		t.Errorf("FindByCode(non-existent) = %+v, want nil", got)
	}
}

// TestCanonicalAdvisoryCodeConstants pins the exported Code* constants
// match the CanonicalAdvisories codes (closes the silent-typo class).
func TestCanonicalAdvisoryCodeConstants(t *testing.T) {
	wantConstants := map[string]string{
		CodePSRAppFraudReimbursementNotReviewed: "MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED",
		CodeAMLSARFilingPlaceholder:             "MONEYCHECK_AML_SAR_FILING_PLACEHOLDER",
		CodeFCACRD4DisclosureRequired:           "MONEYCHECK_FCA_CRD_4_DISCLOSURE_REQUIRED",
		CodePSD2SCAEscapeInvariant:              "MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT",
		CodeReviewedByCounselFalse:              "MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE",
	}
	for got, want := range wantConstants {
		if got != want {
			t.Errorf("constant value = %q, want %q", got, want)
		}
	}
}
