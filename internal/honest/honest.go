// Package honest — R143 LOUD-ONCE-WARNING-FLAG + R143.A severity
// ladder for moneycheck.
//
// 2026-05-27 new-flagship-inception ship. Pure-stdlib; zero deps.
// Surfaces moneycheck's Phase 1 scaffold disclosure as cohort-aligned
// R143 LOUD-ONCE-WARN advisories. The MVP scaffold is honestly
// Phase-1: every load-bearing surface (PSR APP reimbursement
// disposition, AML SAR filing wire format, FCA Conduct of Business 4
// disclosure rendering, PSD2 SCA escape gate, counsel-review evidence)
// is documented as deferred via R143 LOUD-ONCE-WARN advisories.
//
// R143 LOUD-ONCE-WARNING-FLAG promotion (godfather memory 2026-05-11,
// 4/3 saturation): the canonical cohort shape for surfacing degraded-
// mode operation. The literal `[LOUD-ONCE-WARNING]` prefix is the
// cohort-grep contract — every emit across the ecosystem starts with
// it so a single grep across logs surfaces every degraded-mode
// instance.
//
// R143.A SEVERITY-LADDER-CONVENTION (godfather memory 2026-05-26,
// promoted in batch 9 with R143 sub-classes): three severity tiers —
//
//	Error    — regulator-strict-liability staleness. The named
//	           advisory MUST fire on every Phase 1 disposition surface
//	           call that lacks counsel review; production deploys MUST
//	           refuse to proceed.
//	Warn     — honesty-defaults staleness. Surfaces a gap that does not
//	           halt production but should not be ignored.
//	Info     — phase-deferral disclosure. Acceptable for Phase 1 + 2
//	           scaffold; surfaces presence not absence of expected
//	           feature.
//
// moneycheck-specific Phase 1 advisories (the 5 named by the brief):
//
//	MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED — Error
//	    The PSR disposition surface ran against the placeholder
//	    reimbursement-eligibility evaluator. Phase 2 wires the real
//	    PSR 2024 reimbursement-eligibility tree.
//
//	MONEYCHECK_AML_SAR_FILING_PLACEHOLDER — Error
//	    The AML SAR filer surfaced a SAR candidate against the
//	    placeholder NCA envelope encoder. Phase 3 wires the real NCA
//	    SAR-Online v2 envelope.
//
//	MONEYCHECK_FCA_CRD_4_DISCLOSURE_REQUIRED — Warn
//	    FCA Conduct of Business 4 disclosure renderer surfaced text
//	    before counsel review attested ReviewedByCounsel=true.
//
//	MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT — Error
//	    The SCA escape gate triggered (R153-shape regulatory-escape
//	    invariant — refusing-to-decide is the safest path). The
//	    transaction was halted.
//
//	MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE — Warn
//	    The public-API disposition surface was called with
//	    ReviewedByCounsel=false. R166 LIABILITY-FOOTER-CONST sibling.
//
// Cross-substrate parity: byte-aligned `[LOUD-ONCE-WARNING]` prefix
// + Code + Message + DocLink shape with the cohort canonical
// (atelier uplift / canvas uplift / paradox / forge-central / casino /
// ledger R143 emitters).
package honest

import (
	"io"
	"log"
	"os"
	"sync"
)

// LoudOncePrefix is the cohort-canonical prefix every advisory emit
// starts with. Pinned byte-identically across the R143 cohort.
const LoudOncePrefix = "[LOUD-ONCE-WARNING]"

// Severity is the closed-set R143.A severity-ladder label. Per
// godfather memory 2026-05-26 R143.A SEVERITY-LADDER-CONVENTION:
// three tiers (Error / Warn / Info).
type Severity int

const (
	// SeverityInfo — informational only (e.g. phase-deferral
	// disclosure; surfaces presence not absence of expected feature).
	SeverityInfo Severity = iota

	// SeverityWarn — honesty-defaults staleness. Surfaces a gap that
	// does not halt production but should not be ignored.
	SeverityWarn

	// SeverityError — regulator-strict-liability staleness. Production
	// deploys MUST refuse to proceed when the advisory fires; the load-
	// bearing tier for Phase 1 scaffold disclosure of MISSING
	// counsel-reviewed regulatory infrastructure.
	SeverityError
)

// String returns the canonical name for a Severity.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarn:
		return "warn"
	case SeverityError:
		return "error"
	}
	return "unknown"
}

// Advisory is the cohort-canonical R143 advisory shape.
type Advisory struct {
	// Code is the canonical machine-grep identifier (e.g.
	// MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED). MUST be
	// non-empty + stable across releases (downstream grep depends
	// on it).
	Code string

	// Severity is the R143.A severity-ladder tier for this advisory.
	Severity Severity

	// Message is the human-readable explanation of the degraded
	// mode or architectural gate. Forensic-readability aid; the
	// Code is the grep contract.
	Message string

	// DocLink is the canonical docs path explaining the advisory
	// in detail. SHOULD point at ARCHITECTURE.md / CONTEXT.md /
	// SECURITY.md.
	DocLink string
}

// String returns the canonical multi-line representation of an
// Advisory suitable for log output. Includes the LoudOncePrefix.
func (a Advisory) String() string {
	return LoudOncePrefix + " moneycheck: " + a.Code + " (" + a.Severity.String() + ") — " + a.Message + " [see " + a.DocLink + "]"
}

// loudOnceState tracks which Codes have already been emitted; per
// godfather R143 canonical shape, each advisory emits exactly ONCE
// per process lifetime.
type loudOnceState struct {
	mu   sync.Mutex
	seen map[string]bool
}

var defaultState = &loudOnceState{seen: make(map[string]bool)}

// LoudOnce emits Advisory.String() to w iff this Code has not been
// emitted before in this process. Subsequent calls with the same
// Code are silent.
//
// Distinct Codes emit independently. Process-global state
// (sync.Mutex-guarded map); call site is goroutine-safe.
//
// Returns true iff the advisory was actually emitted (i.e. first
// time this Code surfaced).
func LoudOnce(adv Advisory, w io.Writer) bool {
	if adv.Code == "" {
		// Refuse to emit advisories with empty Code — grep contract
		// requires the Code be stable. An empty Code violates the
		// cohort grep contract.
		return false
	}
	defaultState.mu.Lock()
	defer defaultState.mu.Unlock()
	if defaultState.seen[adv.Code] {
		return false
	}
	defaultState.seen[adv.Code] = true
	if w == nil {
		w = os.Stderr
	}
	_, _ = io.WriteString(w, adv.String()+"\n")
	return true
}

// LoudOnceLog is the convenience entry point routing to log.Default()
// rather than a caller-provided writer. Most production callers use
// this; tests use LoudOnce with a captured buffer.
func LoudOnceLog(adv Advisory) bool {
	if adv.Code == "" {
		return false
	}
	defaultState.mu.Lock()
	defer defaultState.mu.Unlock()
	if defaultState.seen[adv.Code] {
		return false
	}
	defaultState.seen[adv.Code] = true
	log.Print(adv.String())
	return true
}

// Reset clears the process-global emit state. Intended for tests
// that need to re-test the first-time-emit path; production code
// MUST NOT call this (would re-emit every advisory on next call).
func Reset() {
	defaultState.mu.Lock()
	defer defaultState.mu.Unlock()
	defaultState.seen = make(map[string]bool)
}

// Canonical advisory codes — exported as constants so callers can
// reference them by symbol rather than by string-literal, closing the
// silent-typo class.
const (
	CodePSRAppFraudReimbursementNotReviewed = "MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED"
	CodeAMLSARFilingPlaceholder             = "MONEYCHECK_AML_SAR_FILING_PLACEHOLDER"
	CodeFCACRD4DisclosureRequired           = "MONEYCHECK_FCA_CRD_4_DISCLOSURE_REQUIRED"
	CodePSD2SCAEscapeInvariant              = "MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT"
	CodeReviewedByCounselFalse              = "MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE"
)

// CanonicalAdvisories returns the canonical moneycheck-specific
// advisories. Used by tests + diagnostic / readiness handlers to
// enumerate all known degraded-mode signals.
//
// Per the brief: 5 named advisories spanning the R143.A 3-tier ladder
// (3 Error + 2 Warn).
func CanonicalAdvisories() []Advisory {
	return []Advisory{
		{
			Code:     CodePSRAppFraudReimbursementNotReviewed,
			Severity: SeverityError,
			Message:  "PSR disposition surface ran against the placeholder reimbursement-eligibility evaluator. Phase 2 wires the real PSR 2024 reimbursement-eligibility tree; until then every disposition is informational and MUST NOT be used as the basis for a real reimbursement decision.",
			DocLink:  "CONTEXT.md §3 + ARCHITECTURE.md §3",
		},
		{
			Code:     CodeAMLSARFilingPlaceholder,
			Severity: SeverityError,
			Message:  "AML SAR filer surfaced a SAR candidate against the placeholder NCA envelope encoder. Phase 3 wires the real NCA SAR-Online v2 envelope; until then the SAR candidate is informational only. POCA §330 still applies; the operator MUST file the SAR through an authorised channel.",
			DocLink:  "CONTEXT.md §3 + ARCHITECTURE.md §3",
		},
		{
			Code:     CodeFCACRD4DisclosureRequired,
			Severity: SeverityWarn,
			Message:  "FCA Conduct of Business 4 disclosure renderer surfaced text before counsel review attested ReviewedByCounsel=true. The text is plausible but legally non-binding; the disclosure surfaces the gap.",
			DocLink:  "CONTEXT.md §3 + R166 LIABILITY-FOOTER-CONST",
		},
		{
			Code:     CodePSD2SCAEscapeInvariant,
			Severity: SeverityError,
			Message:  "The SCA escape gate triggered (R153-shape regulatory-escape invariant — refusing-to-decide is the safest path). The transaction was halted; the operator MUST review the SCA-exemption claim before any re-submission.",
			DocLink:  "ARCHITECTURE.md §4 + R153 R-DOMAIN-ESCAPE-INVARIANT",
		},
		{
			Code:     CodeReviewedByCounselFalse,
			Severity: SeverityWarn,
			Message:  "The public-API disposition surface was called with ReviewedByCounsel=false. The R166 LIABILITY-FOOTER-CONST footer is rendered with ReviewedByCounsel=false and the operator is warned that the surface is informational-only until counsel review attests true.",
			DocLink:  "ARCHITECTURE.md §6 + R166 LIABILITY-FOOTER-CONST",
		},
	}
}

// FindByCode returns the canonical Advisory for the given code, or
// nil if no canonical advisory matches. Linear scan; cohort canonical
// inventory is small (5 advisories).
func FindByCode(code string) *Advisory {
	for _, adv := range CanonicalAdvisories() {
		if adv.Code == code {
			out := adv
			return &out
		}
	}
	return nil
}
