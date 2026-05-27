# moneycheck

UK Payment Services Regulations (PSR) authorised-push-payment (APP)
fraud reimbursement gate + AML Suspicious Activity Report (SAR) filing
infrastructure for UK fintechs subject to Financial Conduct Authority
(FCA) supervision.

**Substrate:** Go 1.22, pure stdlib, zero external dependencies.

**Status:** Phase 1 MVP scaffold. Cohort posture: **R174 5-of-5 cohort
maturity FROM INCEPTION**.

---

## What moneycheck is

A composable Go library + CLI that lets a UK Payment Services Provider
(PSP) — bank, e-money institution, payment institution — gate
authorised-push-payment transfers against the PSR 2017 +
PSR (Amendment) Regulations 2024 reimbursement scheme AND emit AML SAR
filings to the National Crime Agency (NCA) under the Proceeds of Crime
Act 2002 (POCA) suspicious-activity reporting regime.

The scaffold is **honestly Phase 1**: every load-bearing surface
(PSR APP reimbursement disposition, AML SAR filing wire format, FCA
Conduct of Business 4 disclosure rendering, PSD2 Strong Customer
Authentication escape gate, counsel-review evidence) is documented as
deferred via `internal/honest/` R143 LOUD-ONCE-WARN advisories. Phase 2
wires the disposition into a real PSP's payment-rail integration; Phase 3
adds the NCA SAR XML envelope shipping.

---

## Why moneycheck exists

Per BR6 in the cross-pollination overnight-3 brainstorm (rank #2 in the
$5.13M Y1 ARR cohort, $1.5M Y1 alone): UK fintech PSPs subject to FCA
supervision are under simultaneous regulatory pressure from:

1. **PSR APP fraud reimbursement** (October 2024 mandatory regime): PSPs
   MUST reimburse APP fraud victims within five business days unless one
   of two named exceptions applies. Failure to do so is an enforceable
   FCA breach.
2. **POCA SAR filing** (continuous obligation): PSPs MUST file SARs with
   the NCA for any transaction giving rise to reasonable suspicion of
   money laundering or terrorist financing. Failure to do so is a
   criminal offence under POCA §330.
3. **PSD2 Strong Customer Authentication** (regulatory technical
   standard): Two-factor authentication MUST be enforced for payment
   initiation unless one of the closed-list exemptions applies (low-
   value, recurring beneficiary, trusted beneficiary, corporate, etc).

These three regimes compose: an APP-fraud transaction that bypassed SCA
under a fraudulent exemption is BOTH a PSR reimbursement event AND a
POCA SAR-filing trigger AND an SCA-escape-invariant violation. moneycheck
is the single Go library that captures the composability and gives a
PSP one cohort surface to wire into payment-rail integration.

---

## Cohort posture (R174 5-of-5 from inception)

moneycheck ships **all five cohort disciplines** in dedicated packages
from inception, per R174 R-COHORT-5-OF-5-MATURITY (promoted 2026-05-27
Batch 4):

| Package | Discipline | Files |
|---|---|---|
| `internal/firewall/` | R145.C FIREWALL-TEST-DISCIPLINE | `firewall_test.go` |
| `internal/lore/` | R151 KAT-AS-COHORT-INVARIANT-PIN | `kat1.go` + `kat1_test.go` |
| `internal/mirrormark/` | L43 Mirror-Mark v1 signer (production-wired) | `marker.go` + `marker_test.go` |
| `internal/manifest/` | R150 PARALLEL-MAP review-metadata envelope | `manifest.go` + `seed.go` + `manifest_test.go` |
| `internal/honest/` | R143 LOUD-ONCE-WARNING-FLAG + R143.A severity ladder | `honest.go` + `honest_test.go` |

Plus three domain packages composing the PSR + AML + audit-ledger surface:

| Package | Domain | Files |
|---|---|---|
| `internal/psr_app_fraud/` | PSR 2017 + PSR (Amendment) 2024 APP reimbursement disposition | `psr.go` + `psr_test.go` |
| `internal/aml_sar/` | POCA §330 + NCA SAR filing placeholder | `sar.go` + `sar_test.go` |
| `internal/audit_ledger/` | Append-only audit ledger (Mirror-Mark wired) | `ledger.go` + `ledger_test.go` |

R174 + R175: Mirror-Mark is **WIRED FROM INCEPTION** at every audit-
ledger emit path. The `internal/audit_ledger/ledger.go` Emit function
stamps every entry with a Mirror-Mark v1 HMAC over the canonical entry
body. A downstream regulator (FCA / NCA) holding (lore corpus, entry
bytes with `mirror_mark` cleared, the PSP's iik_ key) can cold-verify
the mark without trusting the PSP's filesystem.

---

## Quick start

```bash
go build ./...
go test ./...
go run ./cmd/moneycheck
```

---

## R143 LOUD-ONCE-WARN advisories (Phase 1 scaffold disclosure)

The MVP scaffold ships five named R143 advisories that fire LOUD-ONCE
per process when the corresponding placeholder is active:

| Code | Severity | Triggered when |
|---|---|---|
| `MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED` | Error | PSR disposition called against the placeholder reimbursement-eligibility evaluator (Phase 2 deferred) |
| `MONEYCHECK_AML_SAR_FILING_PLACEHOLDER` | Error | AML SAR filer called against the placeholder NCA-envelope encoder (Phase 3 deferred) |
| `MONEYCHECK_FCA_CRD_4_DISCLOSURE_REQUIRED` | Warn | FCA Conduct of Business 4 disclosure renderer called before counsel review attests `ReviewedByCounsel=true` |
| `MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT` | Error | SCA escape gate triggered (R153 LIFE_SAFETY-shape regulatory-escape invariant — refusing-to-decide is the safest path) |
| `MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE` | Warn | Public-API disposition surface called while counsel-review attestation is `false` (R166 LIABILITY-FOOTER-CONST sibling) |

---

## Regulatory footprint

- **PSR 2017** (UK SI 2017/752) + **PSR (Amendment) Regulations 2024**
  (the APP-fraud reimbursement regime): `internal/psr_app_fraud/` is the
  disposition surface. The named-exception closed set is the load-
  bearing escape-invariant per R153.
- **POCA 2002 §330** + **Money Laundering Regulations 2017** (MLR 2017):
  `internal/aml_sar/` is the SAR-filing placeholder. The NCA envelope
  encoder is Phase 3.
- **FCA Conduct of Business Sourcebook (COBS) 4**: customer
  communication standard for risk disclosure; the renderer is
  `internal/honest/` advisory-driven and gated by counsel review.
- **PSD2 Regulatory Technical Standard on SCA** (Commission Delegated
  Regulation (EU) 2018/389): the SCA escape gate in
  `internal/psr_app_fraud/` cross-references this for ineligible-SCA-
  exemption flags.

---

## License

Apache License 2.0. See `LICENSE`.
