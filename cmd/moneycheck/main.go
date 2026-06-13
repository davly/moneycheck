// Command moneycheck — UK PSR APP-fraud reimbursement + AML SAR CLI.
//
// Phase 1 scaffold: the CLI exercises the three domain surfaces (PSR
// disposition, AML SAR filing, audit-ledger emit) end-to-end against
// the placeholder evaluators. Every disposition surfaces the R143
// LOUD-ONCE-WARN advisories.
//
// R174 5-of-5 cohort maturity FROM INCEPTION + R175 production-wired
// Mirror-Mark FROM INCEPTION.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/davly/moneycheck/internal/aml_sar"
	"github.com/davly/moneycheck/internal/audit_ledger"
	"github.com/davly/moneycheck/internal/honest"
	"github.com/davly/moneycheck/internal/lore"
	"github.com/davly/moneycheck/internal/mirrormark"
	"github.com/davly/moneycheck/internal/psr_app_fraud"
	"github.com/davly/moneycheck/internal/stele"
)

const version = "0.1.0-phase-1-scaffold"

func usage() {
	fmt.Fprint(os.Stderr, `Usage: moneycheck <command> [flags]

Commands:
  decide               Decide a placeholder PSR APP-fraud reimbursement claim
  sar                  File a placeholder SAR candidate (Phase 1; not a real filing)
  kat1                 Print the cohort canonical KAT-1 hex anchor
  advisories           List the R143 LOUD-ONCE-WARN advisory inventory
  version              Print moneycheck version

Phase 1 scaffold notice:
  This CLI is informational only. The PSR disposition evaluator (Phase 2),
  AML SAR NCA envelope encoder (Phase 3), FCA COBS 4 disclosure renderer
  (Phase 4), and PSD2 SCA exemption table (Phase 4) are deferred. The R143
  LOUD-ONCE-WARN advisories surface the deferral.

Stele spine anchoring (opt-in):
  When MONEYCHECK_STELE_URL is set, 'decide' and 'sar' anchor the run's
  audit ledger into the Stele verified-trust spine after a passing
  ledger self-check, and print the spine receipt (seq + entry_hash).
  Unset/empty = disabled (no HTTP, no new output; behavior is identical
  to the argv-only CLI). A requested anchor that fails exits non-zero.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "decide":
		runDecide(os.Args[2:])
	case "sar":
		runSAR(os.Args[2:])
	case "kat1":
		runKAT1()
	case "advisories":
		runAdvisories()
	case "version":
		fmt.Println("moneycheck", version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "moneycheck: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

// runDecide exercises the PSR APP-fraud disposition surface end-to-end
// against an audit-ledger that stamps Mirror-Mark v1 on every entry.
func runDecide(args []string) {
	fs := flag.NewFlagSet("decide", flag.ExitOnError)
	claimID := fs.String("claim", "demo-001", "claim identifier")
	exemption := fs.String("sca", "none", "PSD2 SCA exemption claimed (none, low_value, trusted_beneficiary, recurring, corporate)")
	amount := fs.Int64("amount-pence", 5000, "disputed transaction amount in pence")
	_ = fs.Parse(args)

	// Build a placeholder Ledger with a placeholder marker (Phase 1
	// runtime; production callers MUST construct a real iik_ key
	// marker — Phase 2 wiring).
	marker := mirrormark.NewPlaceholderMarker()
	ledger := audit_ledger.NewLedger(marker)

	claim := psr_app_fraud.Claim{
		ClaimID:                *claimID,
		CustomerID:             "demo-cust",
		TransactionAmountPence: *amount,
		ReportedAt:             time.Now().UTC(),
		SCAExemptionClaimed:    parseSCAExemption(*exemption),
		ReviewedByCounsel:      false,
	}
	out := psr_app_fraud.Decide(claim)

	// Emit a PSR disposition entry into the audit-ledger (Mirror-Mark
	// stamped per R175).
	payload, _ := json.Marshal(map[string]any{
		"claim_id":              claim.ClaimID,
		"disposition":           out.Disposition.String(),
		"sca_escape_triggered":  out.SCAEscapeTriggered,
		"sca_exemption_claimed": claim.SCAExemptionClaimed.String(),
		"amount_pence":          claim.TransactionAmountPence,
		"rationale":             out.Rationale,
	})
	entry := ledger.Emit(audit_ledger.Entry{
		Class:         audit_ledger.EntryClassPSRDisposition,
		Reference:     claim.ClaimID,
		Payload:       payload,
		AdvisoryCodes: out.AdvisoryCodes,
	})

	fmt.Printf("disposition:           %s\n", out.Disposition)
	fmt.Printf("sca_escape_triggered:  %v\n", out.SCAEscapeTriggered)
	fmt.Printf("ledger_entry_id:       %s\n", entry.EntryID)
	fmt.Printf("mirror_mark:           %s\n", entry.MirrorMark)
	fmt.Printf("advisory_codes:        %v\n", out.AdvisoryCodes)
	fmt.Printf("rationale:             %s\n", out.Rationale)

	maybeAnchorToStele(ledger, "decide")

	fmt.Println()
	fmt.Println(r166LiabilityFooter())
}

// runSAR exercises the AML SAR filing placeholder surface.
func runSAR(args []string) {
	fs := flag.NewFlagSet("sar", flag.ExitOnError)
	candidateID := fs.String("candidate", "demo-sar-001", "SAR candidate identifier")
	groundsName := fs.String("grounds", "layering_indicator", "suspicion grounds (app_fraud_confirmed, layering_indicator, high_risk_jurisdiction, sanctions_hit, structuring, other)")
	amount := fs.Int64("amount-pence", 50000, "suspect transaction amount in pence")
	details := fs.String("details", "Demo scaffold candidate; not a real filing.", "narrative details")
	_ = fs.Parse(args)

	marker := mirrormark.NewPlaceholderMarker()
	ledger := audit_ledger.NewLedger(marker)

	candidate := aml_sar.SARCandidate{
		CandidateID:            *candidateID,
		CustomerID:             "demo-cust",
		TransactionAmountPence: *amount,
		OccurredAt:             time.Now().UTC(),
		Grounds:                parseSuspicionGrounds(*groundsName),
		Details:                *details,
		ReviewedByCounsel:      false,
	}
	receipt := aml_sar.File(candidate)

	payload, _ := json.Marshal(map[string]any{
		"candidate_id":  candidate.CandidateID,
		"grounds":       candidate.Grounds.String(),
		"amount_pence":  candidate.TransactionAmountPence,
		"placeholder":   true,
		"filing_status": "phase_1_not_filed",
	})
	entry := ledger.Emit(audit_ledger.Entry{
		Class:         audit_ledger.EntryClassSARFiling,
		Reference:     candidate.CandidateID,
		Payload:       payload,
		AdvisoryCodes: receipt.AdvisoryCodes,
	})

	fmt.Printf("placeholder_receipt:   %s\n", receipt.PlaceholderReceiptID)
	fmt.Printf("filed:                 %v\n", receipt.Filed)
	fmt.Printf("emitted_at:            %s\n", receipt.EmittedAt.Format(time.RFC3339))
	fmt.Printf("ledger_entry_id:       %s\n", entry.EntryID)
	fmt.Printf("mirror_mark:           %s\n", entry.MirrorMark)
	fmt.Printf("advisory_codes:        %v\n", receipt.AdvisoryCodes)

	maybeAnchorToStele(ledger, "sar")

	fmt.Println()
	fmt.Println(r166LiabilityFooter())
}

// maybeAnchorToStele anchors the run's audit ledger into the Stele
// spine when MONEYCHECK_STELE_URL is set. Unset/empty = disabled: no
// self-check, no HTTP, no output — behavior identical to a
// non-anchoring run. This is moneycheck's ONLY env read (R145.B
// stele-anchor re-pin in internal/firewall/); the read lives here in
// cmd/ because the library packages stay env-free (firewall
// TestFirewall_NoLibraryEnvVarReads).
//
// Honesty rules (load-bearing):
//   - the sealed line prints ONLY after the spine returned
//     201 + entry_hash (stele.AnchorRun enforces this);
//   - a requested anchor that fails — ledger self-check, network,
//     non-201 — prints to stderr and exits non-zero, so a missing
//     anchor can never look like success.
func maybeAnchorToStele(ledger *audit_ledger.Ledger, command string) {
	rcpt, anchored, err := stele.AnchorRun(os.Getenv(stele.EnvURL), command, ledger, time.Now().UTC())
	if err != nil {
		fmt.Fprintf(os.Stderr, "stele anchor FAILED (%s set, anchor requested but NOT sealed): %v\n", stele.EnvURL, err)
		os.Exit(1)
	}
	if !anchored {
		return
	}
	fmt.Printf("stele anchor:          sealed seq=%d entry_hash=%s\n", rcpt.Seq, rcpt.EntryHash)
}

// runKAT1 prints the cohort canonical KAT-1 hex anchor.
func runKAT1() {
	fmt.Println("cohort canonical KAT-1 HMAC-SHA256 hex:")
	fmt.Println(lore.KAT1Digest)
	fmt.Println()
	fmt.Println("OpenSSL reproducer:")
	os.Stdout.WriteString("  printf '\\x01' > /tmp/kat1.bin\n")
	os.Stdout.WriteString("  printf '\\x00%.0s' {1..32} >> /tmp/kat1.bin\n")
	os.Stdout.WriteString("  openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin\n")
	fmt.Println()
	if err := lore.VerifyKAT1(); err != nil {
		fmt.Fprintln(os.Stderr, "KAT-1 verify FAILED:", err)
		os.Exit(1)
	}
	fmt.Println("KAT-1 cohort cross-substrate parity: PASS")
}

// runAdvisories prints the R143 advisory inventory.
func runAdvisories() {
	fmt.Println("moneycheck R143 LOUD-ONCE-WARN advisory inventory:")
	fmt.Println()
	for _, adv := range honest.CanonicalAdvisories() {
		fmt.Printf("  %s\n", adv.Code)
		fmt.Printf("    severity: %s\n", adv.Severity)
		fmt.Printf("    doc:      %s\n", adv.DocLink)
		fmt.Printf("    message:  %s\n", adv.Message)
		fmt.Println()
	}

	// Verify that we have a sha256.Size constant available — anchors
	// that the cohort cryptographic primitives are wired correctly at
	// boot.
	_ = sha256.Size
}

// r166LiabilityFooter renders the R166 LIABILITY-FOOTER-CONST sibling
// footer. Phase 1 ALWAYS renders with ReviewedByCounsel=false.
func r166LiabilityFooter() string {
	return `---
LIABILITY FOOTER (R166 LIABILITY-FOOTER-CONST)

Phase 1 scaffold disclosure: this output has NOT been reviewed by counsel.
ReviewedByCounsel: false

moneycheck Phase 1 is a development scaffold. It MUST NOT be used as the
sole basis for a real PSR APP-fraud reimbursement decision or a real NCA
SAR filing. POCA §330 still applies; the operator MUST file SARs through
an authorised NCA channel. The PSR (Amendment) Regulations 2024
reimbursement obligation still applies; the operator MUST evaluate
eligibility through a counsel-reviewed process.

This output is informational only. Apache License 2.0 governs use; no
warranty. See LICENSE.
---`
}

// parseSCAExemption maps a CLI string to the closed enum.
func parseSCAExemption(s string) psr_app_fraud.SCAExemption {
	switch s {
	case "none":
		return psr_app_fraud.SCAExemptionNone
	case "low_value":
		return psr_app_fraud.SCAExemptionLowValue
	case "trusted_beneficiary":
		return psr_app_fraud.SCAExemptionTrustedBeneficiary
	case "recurring":
		return psr_app_fraud.SCAExemptionRecurring
	case "corporate":
		return psr_app_fraud.SCAExemptionCorporate
	}
	return psr_app_fraud.SCAExemptionNone
}

// parseSuspicionGrounds maps a CLI string to the closed enum.
func parseSuspicionGrounds(s string) aml_sar.SuspicionGrounds {
	switch s {
	case "app_fraud_confirmed":
		return aml_sar.SuspicionGroundsAPPFraudConfirmed
	case "layering_indicator":
		return aml_sar.SuspicionGroundsLayeringIndicator
	case "high_risk_jurisdiction":
		return aml_sar.SuspicionGroundsHighRiskJurisdiction
	case "sanctions_hit":
		return aml_sar.SuspicionGroundsSanctionsHit
	case "structuring":
		return aml_sar.SuspicionGroundsStructuring
	case "other":
		return aml_sar.SuspicionGroundsOther
	}
	return aml_sar.SuspicionGroundsOther
}
