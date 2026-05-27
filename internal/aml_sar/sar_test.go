package aml_sar

import (
	"strings"
	"testing"
	"time"

	"github.com/davly/moneycheck/internal/honest"
)

// TestSuspicionGroundsClosedSet pins the 6-state closed enum.
func TestSuspicionGroundsClosedSet(t *testing.T) {
	pairs := []struct {
		s    SuspicionGrounds
		name string
	}{
		{SuspicionGroundsAPPFraudConfirmed, "app_fraud_confirmed"},
		{SuspicionGroundsLayeringIndicator, "layering_indicator"},
		{SuspicionGroundsHighRiskJurisdiction, "high_risk_jurisdiction"},
		{SuspicionGroundsSanctionsHit, "sanctions_hit"},
		{SuspicionGroundsStructuring, "structuring"},
		{SuspicionGroundsOther, "other"},
	}
	for i, p := range pairs {
		if int(p.s) != i {
			t.Errorf("SuspicionGrounds %q ordinal = %d, want %d", p.name, int(p.s), i)
		}
		if got := p.s.String(); got != p.name {
			t.Errorf("SuspicionGrounds(%d).String() = %q, want %q", p.s, got, p.name)
		}
	}
}

// TestFile_AlwaysReturnsPlaceholder pins the Phase 1 contract: File
// always returns a placeholder receipt with Filed=false.
func TestFile_AlwaysReturnsPlaceholder(t *testing.T) {
	honest.Reset()
	defer honest.Reset()

	candidate := SARCandidate{
		CandidateID:            "sar-001",
		CustomerID:             "cust-xyz",
		TransactionAmountPence: 100_00,
		OccurredAt:             time.Now(),
		Grounds:                SuspicionGroundsLayeringIndicator,
		Details:                "Pattern suggests structuring across 12 sub-£10k transactions in 48 hours.",
		ReviewedByCounsel:      true,
	}
	receipt := File(candidate)

	if receipt.Filed {
		t.Error("FilingReceipt.Filed = true, want false (Phase 1 never files)")
	}
	if receipt.CandidateID != "sar-001" {
		t.Errorf("CandidateID = %q, want %q", receipt.CandidateID, "sar-001")
	}
	if !strings.HasPrefix(receipt.PlaceholderReceiptID, PlaceholderReceiptPrefix) {
		t.Errorf("PlaceholderReceiptID = %q, want prefix %q", receipt.PlaceholderReceiptID, PlaceholderReceiptPrefix)
	}
	if !strings.Contains(receipt.PlaceholderReceiptID, "sar-001") {
		t.Errorf("PlaceholderReceiptID = %q, want to contain candidate id", receipt.PlaceholderReceiptID)
	}
}

// TestFile_AMLAdvisoryAlwaysFires pins R143.A Error severity —
// MONEYCHECK_AML_SAR_FILING_PLACEHOLDER appears in every call's
// advisory list.
func TestFile_AMLAdvisoryAlwaysFires(t *testing.T) {
	honest.Reset()
	defer honest.Reset()

	candidate := SARCandidate{CandidateID: "sar-002", ReviewedByCounsel: true}
	receipt := File(candidate)
	if !sliceContains(receipt.AdvisoryCodes, honest.CodeAMLSARFilingPlaceholder) {
		t.Errorf("AdvisoryCodes = %v, want to contain %q", receipt.AdvisoryCodes, honest.CodeAMLSARFilingPlaceholder)
	}
}

// TestFile_R166AdvisoryFiresOnNotReviewed pins R166 — when
// ReviewedByCounsel=false, the MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE
// advisory is registered.
func TestFile_R166AdvisoryFiresOnNotReviewed(t *testing.T) {
	honest.Reset()
	defer honest.Reset()

	candidate := SARCandidate{CandidateID: "sar-003", ReviewedByCounsel: false}
	receipt := File(candidate)
	if !sliceContains(receipt.AdvisoryCodes, honest.CodeReviewedByCounselFalse) {
		t.Errorf("AdvisoryCodes = %v, want to contain %q", receipt.AdvisoryCodes, honest.CodeReviewedByCounselFalse)
	}
}

// TestPlaceholderReceiptPrefixPinned pins the canonical prefix.
func TestPlaceholderReceiptPrefixPinned(t *testing.T) {
	if PlaceholderReceiptPrefix != "MONEYCHECK-P1-PLACEHOLDER-" {
		t.Errorf("PlaceholderReceiptPrefix = %q, want %q", PlaceholderReceiptPrefix, "MONEYCHECK-P1-PLACEHOLDER-")
	}
}

// TestPOCA330MaxImprisonmentPinned pins the statutory maximum.
func TestPOCA330MaxImprisonmentPinned(t *testing.T) {
	if POCA330MaxImprisonmentYears != 5 {
		t.Errorf("POCA330MaxImprisonmentYears = %d, want 5 (POCA 2002 §330)", POCA330MaxImprisonmentYears)
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
