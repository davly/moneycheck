package psr_app_fraud

import (
	"testing"
	"time"

	"github.com/davly/moneycheck/internal/honest"
)

// TestDispositionClosedSet pins the closed 4-state Disposition enum.
func TestDispositionClosedSet(t *testing.T) {
	pairs := []struct {
		d    Disposition
		name string
	}{
		{DispositionPlaceholder, "placeholder"},
		{DispositionReimburse, "reimburse"},
		{DispositionDeny, "deny"},
		{DispositionEscapeToHuman, "escape_to_human"},
	}
	for i, p := range pairs {
		if int(p.d) != i {
			t.Errorf("Disposition %q ordinal = %d, want %d", p.name, int(p.d), i)
		}
		if got := p.d.String(); got != p.name {
			t.Errorf("Disposition(%d).String() = %q, want %q", p.d, got, p.name)
		}
	}
}

// TestSCAExemptionClosedSet pins the closed 5-state SCA exemption enum.
func TestSCAExemptionClosedSet(t *testing.T) {
	pairs := []struct {
		s    SCAExemption
		name string
	}{
		{SCAExemptionNone, "none"},
		{SCAExemptionLowValue, "low_value"},
		{SCAExemptionTrustedBeneficiary, "trusted_beneficiary"},
		{SCAExemptionRecurring, "recurring"},
		{SCAExemptionCorporate, "corporate"},
	}
	for i, p := range pairs {
		if int(p.s) != i {
			t.Errorf("SCAExemption %q ordinal = %d, want %d", p.name, int(p.s), i)
		}
		if got := p.s.String(); got != p.name {
			t.Errorf("SCAExemption(%d).String() = %q, want %q", p.s, got, p.name)
		}
	}
}

// TestSCAEscapeGate_NoneDoesNotEscape pins that exemption=None does
// not trigger the escape gate.
func TestSCAEscapeGate_NoneDoesNotEscape(t *testing.T) {
	if SCAEscapeGate(SCAExemptionNone) {
		t.Error("SCAEscapeGate(None) = true, want false (no exemption claimed)")
	}
}

// TestSCAEscapeGate_AnyExemptionEscapes pins R153 — any non-None
// exemption escapes under Phase 1.
func TestSCAEscapeGate_AnyExemptionEscapes(t *testing.T) {
	for _, exemption := range []SCAExemption{
		SCAExemptionLowValue,
		SCAExemptionTrustedBeneficiary,
		SCAExemptionRecurring,
		SCAExemptionCorporate,
	} {
		if !SCAEscapeGate(exemption) {
			t.Errorf("SCAEscapeGate(%v) = false, want true (R153 Phase 1 always escapes)", exemption)
		}
	}
}

// TestDecide_Phase1ReturnsPlaceholder pins the Phase 1 default
// disposition.
func TestDecide_Phase1ReturnsPlaceholder(t *testing.T) {
	honest.Reset()
	defer honest.Reset()

	claim := Claim{
		ClaimID:                "claim-001",
		CustomerID:             "cust-xyz",
		TransactionAmountPence: 100_00,
		ReportedAt:             time.Now(),
		SCAExemptionClaimed:    SCAExemptionNone,
		ReviewedByCounsel:      true,
	}
	out := Decide(claim)
	if out.Disposition != DispositionPlaceholder {
		t.Errorf("Disposition = %v, want Placeholder (Phase 1 default)", out.Disposition)
	}
	if out.SCAEscapeTriggered {
		t.Error("SCAEscapeTriggered = true, want false (None exemption)")
	}
}

// TestDecide_NonNoneExemptionEscapes pins R153 — SCA exemption claim
// drives the disposition to EscapeToHuman.
func TestDecide_NonNoneExemptionEscapes(t *testing.T) {
	honest.Reset()
	defer honest.Reset()

	claim := Claim{
		ClaimID:                "claim-002",
		CustomerID:             "cust-abc",
		TransactionAmountPence: 50_00,
		ReportedAt:             time.Now(),
		SCAExemptionClaimed:    SCAExemptionLowValue,
		ReviewedByCounsel:      true,
	}
	out := Decide(claim)
	if out.Disposition != DispositionEscapeToHuman {
		t.Errorf("Disposition = %v, want EscapeToHuman (R153 escape)", out.Disposition)
	}
	if !out.SCAEscapeTriggered {
		t.Error("SCAEscapeTriggered = false, want true")
	}

	// Advisory codes should include the SCA escape advisory.
	if !sliceContains(out.AdvisoryCodes, honest.CodePSD2SCAEscapeInvariant) {
		t.Errorf("AdvisoryCodes = %v, want to contain %q", out.AdvisoryCodes, honest.CodePSD2SCAEscapeInvariant)
	}
}

// TestDecide_AdvisoryFiresOnNotReviewed pins R166 + R143 — when
// ReviewedByCounsel=false, the MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE
// advisory is registered.
func TestDecide_AdvisoryFiresOnNotReviewed(t *testing.T) {
	honest.Reset()
	defer honest.Reset()

	claim := Claim{
		ClaimID:           "claim-003",
		ReviewedByCounsel: false,
	}
	out := Decide(claim)
	if !sliceContains(out.AdvisoryCodes, honest.CodeReviewedByCounselFalse) {
		t.Errorf("AdvisoryCodes = %v, want to contain %q", out.AdvisoryCodes, honest.CodeReviewedByCounselFalse)
	}
}

// TestDecide_PSRAdvisoryAlwaysFires pins R143.A Error severity —
// MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED ALWAYS appears
// in the advisory list for Phase 1 disposition (the placeholder
// evaluator is the entire Phase 1 surface).
func TestDecide_PSRAdvisoryAlwaysFires(t *testing.T) {
	honest.Reset()
	defer honest.Reset()

	claim := Claim{ClaimID: "claim-004", ReviewedByCounsel: true}
	out := Decide(claim)
	if !sliceContains(out.AdvisoryCodes, honest.CodePSRAppFraudReimbursementNotReviewed) {
		t.Errorf("Phase 1 Decide() AdvisoryCodes = %v, want to contain %q (always-fires)", out.AdvisoryCodes, honest.CodePSRAppFraudReimbursementNotReviewed)
	}
}

// TestReimbursementCapPinned pins the £415,000 PSR 2024 statutory
// cap. Drift surfaces here.
func TestReimbursementCapPinned(t *testing.T) {
	if ReimbursementCapPence != 41_500_000 {
		t.Errorf("ReimbursementCapPence = %d, want 41_500_000 (£415,000)", ReimbursementCapPence)
	}
}

// sliceContains is a stdlib-only substring check.
func sliceContains(s []string, target string) bool {
	for _, x := range s {
		if x == target {
			return true
		}
	}
	return false
}
