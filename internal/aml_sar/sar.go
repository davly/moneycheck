// Package aml_sar — POCA 2002 §330 + NCA SAR-filing placeholder surface
// for moneycheck.
//
// 2026-05-27 new-flagship-inception ship. Pure-stdlib; zero deps.
// Ships the SAR-filing contract surface as a Phase 1 scaffold.
//
// Phase 1 scope:
//   - SARCandidate is the inbound SAR-filing candidate (transaction +
//     suspicion-trigger metadata).
//   - File() always returns a placeholder ReceiptID + fires the R143
//     LOUD-ONCE-WARN MONEYCHECK_AML_SAR_FILING_PLACEHOLDER advisory.
//
// Phase 3 wires the real NCA SAR-Online v2 envelope encoder on a
// dedicated R145.B sibling-not-stacked branch:
// `phase-3-aml-sar-nca-envelope`.
//
// Regulatory footprint:
//   - Proceeds of Crime Act 2002 §330: failure to file a SAR when
//     suspicion arises is a criminal offence with up to 5 years'
//     imprisonment + unlimited fine.
//   - Money Laundering Regulations 2017 (MLR 2017): the regulatory
//     framework that supports POCA §330 in practice.
//   - NCA SAR-Online v2: the canonical electronic submission channel.
//     Phase 3 envelope encoder is deferred.
//
// IMPORTANT: in Phase 1, this package is **informational only**. The
// PSP MUST file SARs through an authorised NCA channel (SAR-Online v2
// or bulk-report API). Failure to do so is a criminal offence under
// POCA §330; moneycheck Phase 1 does NOT relieve the PSP of this
// obligation.
package aml_sar

import (
	"time"

	"github.com/davly/moneycheck/internal/honest"
)

// SuspicionGrounds is the closed-set enum of suspicion-trigger
// reasons. NOT free-form text. Each value maps to a SAR-Online v2
// `suspicion_grounds` field (Phase 3 envelope mapping).
type SuspicionGrounds int

const (
	// SuspicionGroundsAPPFraudConfirmed — APP fraud confirmed
	// downstream of PSR disposition.
	SuspicionGroundsAPPFraudConfirmed SuspicionGrounds = iota

	// SuspicionGroundsLayeringIndicator — transaction pattern
	// indicative of money-laundering layering.
	SuspicionGroundsLayeringIndicator

	// SuspicionGroundsHighRiskJurisdiction — counterparty in
	// FATF / OFAC high-risk jurisdiction.
	SuspicionGroundsHighRiskJurisdiction

	// SuspicionGroundsSanctionsHit — counterparty matches sanctions
	// list (OFSI / OFAC / EU).
	SuspicionGroundsSanctionsHit

	// SuspicionGroundsStructuring — transaction structured to avoid
	// reporting thresholds.
	SuspicionGroundsStructuring

	// SuspicionGroundsOther — open-ended; Phase 3 envelope will
	// include a free-form `additional_details` field for this case.
	SuspicionGroundsOther
)

// String returns the canonical name for a SuspicionGrounds.
func (s SuspicionGrounds) String() string {
	switch s {
	case SuspicionGroundsAPPFraudConfirmed:
		return "app_fraud_confirmed"
	case SuspicionGroundsLayeringIndicator:
		return "layering_indicator"
	case SuspicionGroundsHighRiskJurisdiction:
		return "high_risk_jurisdiction"
	case SuspicionGroundsSanctionsHit:
		return "sanctions_hit"
	case SuspicionGroundsStructuring:
		return "structuring"
	case SuspicionGroundsOther:
		return "other"
	}
	return "unknown"
}

// SARCandidate is the inbound SAR-filing candidate. Phase 1 scaffold
// shape; Phase 3 may extend additively (e.g. counterparty fields,
// jurisdiction codes, transaction-chain references).
type SARCandidate struct {
	// CandidateID is the PSP-internal identifier for this SAR
	// candidate. Phase 3 envelope uses this as the cross-reference.
	CandidateID string

	// CustomerID is the PSP-internal customer reference (pseudonym).
	CustomerID string

	// TransactionAmountPence is the suspect transaction value in
	// pence.
	TransactionAmountPence int64

	// OccurredAt is when the suspect transaction occurred. POCA §330
	// reporting obligation starts when suspicion arises (post-event).
	OccurredAt time.Time

	// Grounds is the closed-set suspicion-trigger enum.
	Grounds SuspicionGrounds

	// Details is a short narrative (3-5 sentences) describing the
	// suspicion. Phase 3 envelope serialises this as the SAR-Online v2
	// `details` field.
	Details string

	// ReviewedByCounsel signals whether external counsel has signed
	// off on the surface configuration. Phase 1 always false; R166
	// LIABILITY-FOOTER-CONST sibling.
	ReviewedByCounsel bool
}

// FilingReceipt is the Phase 1 placeholder receipt for a SAR-filing
// candidate. Phase 3 will return the NCA SAR-Online v2 `nca_ref` +
// `submission_timestamp` once the envelope encoder is wired.
type FilingReceipt struct {
	// CandidateID is the inbound CandidateID for cross-reference.
	CandidateID string

	// PlaceholderReceiptID is the Phase 1 fake receipt identifier.
	// Phase 3 replaces this with the real NCA `nca_ref` string.
	// Format: "MONEYCHECK-P1-PLACEHOLDER-<candidateID>".
	PlaceholderReceiptID string

	// EmittedAt is when File() processed the candidate (NOT the
	// actual NCA submission timestamp — Phase 1 does not submit).
	EmittedAt time.Time

	// AdvisoryCodes lists the R143 LOUD-ONCE-WARN advisories fired
	// during filing.
	AdvisoryCodes []string

	// Filed is always false in Phase 1. The PSP MUST submit through
	// an authorised NCA channel separately.
	Filed bool
}

// PlaceholderReceiptPrefix is the canonical prefix for Phase 1
// placeholder receipts. Pinned so a downstream consumer can grep for
// it and refuse to treat the receipt as a real NCA filing.
const PlaceholderReceiptPrefix = "MONEYCHECK-P1-PLACEHOLDER-"

// File processes a SAR candidate. Phase 1 ALWAYS returns a placeholder
// receipt + fires the MONEYCHECK_AML_SAR_FILING_PLACEHOLDER advisory.
//
// Phase 3 wires the real NCA SAR-Online v2 envelope encoder. Phase 1
// MUST NOT be used as the basis for a real SAR filing; the PSP MUST
// submit through an authorised NCA channel separately.
//
// The function fires:
//   - MONEYCHECK_AML_SAR_FILING_PLACEHOLDER (Error) — on every call.
//   - MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE (Warn) — when
//     ReviewedByCounsel=false.
//
// All fire per R143 LOUD-ONCE.
func File(candidate SARCandidate) FilingReceipt {
	codes := []string{}

	// Phase 1 always-fires advisory.
	if adv := honest.FindByCode(honest.CodeAMLSARFilingPlaceholder); adv != nil {
		honest.LoudOnceLog(*adv)
		codes = append(codes, adv.Code)
	}

	// R166 sibling.
	if !candidate.ReviewedByCounsel {
		if adv := honest.FindByCode(honest.CodeReviewedByCounselFalse); adv != nil {
			honest.LoudOnceLog(*adv)
			codes = append(codes, adv.Code)
		}
	}

	return FilingReceipt{
		CandidateID:          candidate.CandidateID,
		PlaceholderReceiptID: PlaceholderReceiptPrefix + candidate.CandidateID,
		EmittedAt:            time.Now().UTC(),
		AdvisoryCodes:        codes,
		Filed:                false, // Phase 3 wires this true
	}
}

// POCA330MaxImprisonmentYears is the statutory maximum imprisonment
// under POCA 2002 §330 for failure to file a SAR. Pinned as a
// constant; Phase 3 envelope renderer cites this in operator-facing
// disclosures.
const POCA330MaxImprisonmentYears = 5
