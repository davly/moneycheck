// Package psr_app_fraud — PSR 2017 + PSR (Amendment) 2024
// authorised-push-payment fraud reimbursement disposition surface.
//
// 2026-05-27 new-flagship-inception ship. Pure-stdlib; zero deps.
// Ships the disposition contract surface as a Phase 1 scaffold:
//
//   - Disposition is the closed-set verdict enum (Reimburse / Deny /
//     EscapeToHuman / Placeholder).
//   - Decide() is the placeholder evaluator that ALWAYS returns
//     DispositionPlaceholder + fires the R143 LOUD-ONCE-WARN advisory
//     MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED.
//   - SCAEscapeGate() returns true when the SCA-exemption claim
//     cannot be validated against the Phase 4 exemption table (which
//     is also placeholder).
//
// Phase 2 wires the real PSR 2024 reimbursement-eligibility tree on a
// dedicated R145.B sibling-not-stacked branch:
// `phase-2-psr-app-reimbursement-evaluator`.
//
// Regulatory footprint (PSR (Amendment) Regulations 2024):
//
//   - October 2024 mandatory reimbursement regime took effect.
//   - PSPs MUST reimburse APP fraud victims within 5 business days
//     unless one of two named exceptions applies:
//       1. Gross negligence by the customer (regulation 90A(5)(a))
//       2. First-party fraud (regulation 90A(5)(b))
//   - Failure to reimburse is an enforceable FCA breach.
//   - The reimbursement obligation is up to £415,000 per claim.
//
// R153 LIFE_SAFETY_ESCAPE_INVARIANT shape: when SCA cannot be
// confidently authorised, refuse to decide and escape to a human
// reviewer. The MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT advisory fires
// per R143 LOUD-ONCE on every escape event.
package psr_app_fraud

import (
	"time"

	"github.com/davly/moneycheck/internal/honest"
)

// Disposition is the closed-set verdict for a PSR APP-fraud
// reimbursement decision. Closed enum per R115 SINGLE-ENUM-REJECTION-
// OUTCOME.
type Disposition int

const (
	// DispositionPlaceholder — Phase 1 scaffold default. Always
	// returned by the Phase 1 evaluator. The R143 LOUD-ONCE-WARN
	// MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED advisory
	// fires the first time this disposition is surfaced.
	DispositionPlaceholder Disposition = iota

	// DispositionReimburse — the PSR 2024 reimbursement-eligibility
	// tree returned PSR-eligible. The PSP MUST reimburse within 5
	// business days. Phase 2 surface; Phase 1 never returns this.
	DispositionReimburse

	// DispositionDeny — a PSR 2024 named exception applies (gross
	// negligence or first-party fraud). The PSP may refuse to
	// reimburse, citing the named exception. Phase 2 surface.
	DispositionDeny

	// DispositionEscapeToHuman — R153-shape regulatory-escape invariant.
	// The disposition cannot be confidently authorised by the automated
	// surface; the case escapes to a human reviewer. The R143
	// MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT advisory fires on every
	// escape event.
	DispositionEscapeToHuman
)

// String returns the canonical name for a Disposition.
func (d Disposition) String() string {
	switch d {
	case DispositionPlaceholder:
		return "placeholder"
	case DispositionReimburse:
		return "reimburse"
	case DispositionDeny:
		return "deny"
	case DispositionEscapeToHuman:
		return "escape_to_human"
	}
	return "unknown"
}

// Claim is the inbound APP-fraud reimbursement claim. Phase 1
// scaffold shape; Phase 2 may extend additively.
type Claim struct {
	// ClaimID is the PSP-internal identifier for this claim.
	ClaimID string

	// CustomerID is the PSP-internal customer reference (pseudonym;
	// no PII in moneycheck itself).
	CustomerID string

	// TransactionAmountPence is the disputed transaction value in
	// pence. PSR 2024 reimbursement caps at £415,000 = 41,500,000
	// pence.
	TransactionAmountPence int64

	// ReportedAt is when the customer reported the fraud to the PSP.
	// PSR 2024 reimbursement clock starts here.
	ReportedAt time.Time

	// SCAExemptionClaimed is the closed enum SCA-exemption that was
	// claimed to bypass strong customer authentication on the disputed
	// transaction. Phase 4 wires the exemption-table evaluator.
	SCAExemptionClaimed SCAExemption

	// ReviewedByCounsel signals whether external counsel has signed
	// off on the surface configuration. Phase 1 always false; R166
	// LIABILITY-FOOTER-CONST sibling.
	ReviewedByCounsel bool
}

// SCAExemption is the closed-set PSD2 RTS Article 13-17 exemption
// enum. Phase 4 wires the exemption-table evaluator; Phase 1 always
// escapes per R153 when any non-None exemption is claimed.
type SCAExemption int

const (
	// SCAExemptionNone — no exemption claimed; SCA was performed.
	SCAExemptionNone SCAExemption = iota

	// SCAExemptionLowValue — PSD2 RTS Article 16 low-value exemption.
	SCAExemptionLowValue

	// SCAExemptionTrustedBeneficiary — PSD2 RTS Article 13.
	SCAExemptionTrustedBeneficiary

	// SCAExemptionRecurring — PSD2 RTS Article 14.
	SCAExemptionRecurring

	// SCAExemptionCorporate — PSD2 RTS Article 17.
	SCAExemptionCorporate
)

// String returns the canonical name for an SCAExemption.
func (s SCAExemption) String() string {
	switch s {
	case SCAExemptionNone:
		return "none"
	case SCAExemptionLowValue:
		return "low_value"
	case SCAExemptionTrustedBeneficiary:
		return "trusted_beneficiary"
	case SCAExemptionRecurring:
		return "recurring"
	case SCAExemptionCorporate:
		return "corporate"
	}
	return "unknown"
}

// Outcome bundles the Disposition + supporting reasoning for an
// APP-fraud claim. Returned by Decide().
type Outcome struct {
	// Disposition is the closed-set verdict.
	Disposition Disposition

	// SCAEscapeTriggered is true when the SCA escape gate fired during
	// disposition (R153-shape invariant).
	SCAEscapeTriggered bool

	// Rationale carries a short human-readable explanation. NOT
	// load-bearing; forensic-readability aid only.
	Rationale string

	// AdvisoryCodes lists the R143 LOUD-ONCE-WARN advisories fired
	// during disposition. Useful for downstream filing the SAR + audit
	// ledger entry against the same set of advisories.
	AdvisoryCodes []string
}

// Decide is the Phase 1 placeholder reimbursement-eligibility
// evaluator. ALWAYS returns DispositionPlaceholder for the underlying
// reimbursement question (the real PSR 2024 tree is Phase 2). However,
// it ALSO runs the SCA escape gate, which can independently surface
// DispositionEscapeToHuman when a non-None SCA exemption is claimed
// (R153 saturator).
//
// The function fires:
//   - MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED (Error) — on
//     every call (Phase 1 disclosure).
//   - MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT (Error) — when the SCA
//     escape gate triggers.
//   - MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE (Warn) — when the claim
//     carries ReviewedByCounsel=false.
//
// All three fire per R143 LOUD-ONCE — exactly once per process per
// distinct Code, even across thousands of Decide() calls.
func Decide(c Claim) Outcome {
	codes := []string{}

	// Phase 1 ALWAYS-fires advisory: PSR evaluator is placeholder.
	if adv := honest.FindByCode(honest.CodePSRAppFraudReimbursementNotReviewed); adv != nil {
		honest.LoudOnceLog(*adv)
		codes = append(codes, adv.Code)
	}

	// R166 sibling: counsel review attestation.
	if !c.ReviewedByCounsel {
		if adv := honest.FindByCode(honest.CodeReviewedByCounselFalse); adv != nil {
			honest.LoudOnceLog(*adv)
			codes = append(codes, adv.Code)
		}
	}

	// SCA escape gate (R153 saturator): any non-None exemption
	// triggers escape under Phase 1 + Phase 4 unwired state.
	scaEscape := SCAEscapeGate(c.SCAExemptionClaimed)
	if scaEscape {
		if adv := honest.FindByCode(honest.CodePSD2SCAEscapeInvariant); adv != nil {
			honest.LoudOnceLog(*adv)
			codes = append(codes, adv.Code)
		}
		return Outcome{
			Disposition:        DispositionEscapeToHuman,
			SCAEscapeTriggered: true,
			Rationale:          "PSD2 SCA exemption " + c.SCAExemptionClaimed.String() + " claimed; Phase 4 exemption-table evaluator deferred; R153 regulatory-escape invariant — refusing-to-decide is the safest path.",
			AdvisoryCodes:      codes,
		}
	}

	// Otherwise, return DispositionPlaceholder (Phase 1 evaluator
	// has nothing to say about the underlying reimbursement question).
	return Outcome{
		Disposition:        DispositionPlaceholder,
		SCAEscapeTriggered: false,
		Rationale:          "Phase 1 scaffold: real PSR 2024 reimbursement-eligibility tree is Phase 2. Disposition is informational-only and MUST NOT be used as the basis for a real reimbursement decision. See MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED.",
		AdvisoryCodes:      codes,
	}
}

// SCAEscapeGate returns true when the SCA exemption claimed cannot be
// validated against the Phase 4 exemption table. In Phase 1, ANY
// non-None exemption escapes per R153 (refuse-to-decide is the safest
// path).
//
// R153 R-DOMAIN-ESCAPE-INVARIANT saturator: this function is the
// moneycheck instantiation of the regulator-escape-invariant shape.
// The SCA exemption claim is regulator-strict-liability territory;
// refusing-to-decide is the safest Phase 1 disposition.
func SCAEscapeGate(exemption SCAExemption) bool {
	// Phase 4 will wire the per-exemption evaluator (LowValue ≤ €30,
	// TrustedBeneficiary against whitelist, Recurring against history,
	// Corporate against dedicated-process attestation). Phase 1
	// always escapes when ANY non-None exemption is claimed.
	return exemption != SCAExemptionNone
}

// ReimbursementCapPence is the PSR 2024 statutory reimbursement cap
// per claim. £415,000 = 41,500,000 pence. Pinned as a constant so a
// future amendment cannot silently raise it without paired regression.
const ReimbursementCapPence int64 = 41_500_000
