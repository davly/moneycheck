# CONTEXT — moneycheck

**Substrate:** Go 1.22, pure stdlib, zero external dependencies.

**Cohort posture:** R174 5-of-5 cohort maturity FROM INCEPTION.

**Status:** Phase 1 MVP scaffold. Phase 2 + Phase 3 wiring deferred to
named R145.B sibling-not-stacked branches; named in `internal/honest/`
LOUD-ONCE-WARN advisories.

---

## 1. What moneycheck does

UK PSR (Payment Services Regulations) authorised-push-payment (APP)
fraud reimbursement gate + AML Suspicious Activity Report (SAR) filing
infrastructure. Composes three regulatory regimes into a single Go
library + CLI:

1. **PSR 2017 + PSR (Amendment) Regulations 2024** APP reimbursement
   disposition surface (`internal/psr_app_fraud/`).
2. **POCA 2002 §330** + **Money Laundering Regulations 2017** SAR-
   filing placeholder (`internal/aml_sar/`).
3. **PSD2 Strong Customer Authentication regulatory technical
   standard** SCA escape gate (cross-referenced from PSR disposition).

Plus an append-only audit ledger (`internal/audit_ledger/`) with
Mirror-Mark v1 stamping wired from inception (R174 + R175).

---

## 2. Cohort 5-of-5 package layout (R174 from inception)

| Discipline | Package | Files | Status |
|---|---|---|---|
| R145.C FIREWALL-TEST-DISCIPLINE | `internal/firewall/` | `firewall_test.go` | Shipped |
| R151 KAT-AS-COHORT-INVARIANT-PIN | `internal/lore/` | `kat1.go` + `kat1_test.go` | Shipped |
| L43 Mirror-Mark v1 (R175 production-wired) | `internal/mirrormark/` | `marker.go` + `marker_test.go` | Shipped |
| R150 PARALLEL-MAP review-metadata | `internal/manifest/` | `manifest.go` + `seed.go` + `manifest_test.go` | Shipped |
| R143 LOUD-ONCE-WARN + R143.A ladder | `internal/honest/` | `honest.go` + `honest_test.go` | Shipped |

Plus three domain packages:

| Domain | Package | Files | Phase |
|---|---|---|---|
| PSR APP reimbursement disposition | `internal/psr_app_fraud/` | `psr.go` + `psr_test.go` | Phase 1 scaffold; Phase 2 deferred |
| POCA §330 + NCA SAR filing | `internal/aml_sar/` | `sar.go` + `sar_test.go` | Phase 1 scaffold; Phase 3 deferred |
| Audit-ledger (Mirror-Mark wired) | `internal/audit_ledger/` | `ledger.go` + `ledger_test.go` | Shipped (production-wired emit) |

---

## 3. R143 LOUD-ONCE advisories (Phase 1 disclosure)

The MVP scaffold ships five named R143 advisories. Each fires LOUD-ONCE
per process per the cohort canonical R143 contract. Severity ladder per
R143.A (Error / Warn / Info):

| Code | Severity (R143.A) | What it tells the operator |
|---|---|---|
| `MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED` | **Error** | PSR disposition surfaces ran against the placeholder reimbursement-eligibility evaluator. Phase 2 wires the real PSR 2024 reimbursement-eligibility tree; until then every disposition is informational and MUST NOT be used as the basis for a real reimbursement decision. |
| `MONEYCHECK_AML_SAR_FILING_PLACEHOLDER` | **Error** | AML SAR filer surfaced a SAR candidate against the placeholder NCA envelope encoder. Phase 3 wires the real NCA SAR-Online v2 envelope; until then the SAR candidate is informational only. POCA §330 still applies; the operator MUST file the SAR through an authorised channel. |
| `MONEYCHECK_FCA_CRD_4_DISCLOSURE_REQUIRED` | **Warn** | FCA Conduct of Business 4 disclosure renderer surfaced text before counsel review attested `ReviewedByCounsel=true`. The text is plausible but legally non-binding; the disclosure surfaces the gap. |
| `MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT` | **Error** | The SCA escape gate triggered (R153-shape regulatory-escape invariant — refusing-to-decide is the safest path). The transaction was halted; the operator MUST review the SCA-exemption claim before any re-submission. |
| `MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE` | **Warn** | The public-API disposition surface was called with `ReviewedByCounsel=false`. The R166 LIABILITY-FOOTER-CONST footer is rendered with `ReviewedByCounsel=false` and the operator is warned that the surface is informational-only until counsel review attests true. |

---

## 4. R145 ADDITIVE-FIRST contract (cohort + domain composition)

moneycheck is a Phase 1 scaffold; every behavior-changing wire-in is
deferred to a named R145.B sibling-not-stacked branch:

- Phase 2 PSR APP reimbursement-eligibility wiring branch:
  `phase-2-psr-app-reimbursement-evaluator` (deferred).
- Phase 3 AML SAR NCA-envelope encoder branch:
  `phase-3-aml-sar-nca-envelope` (deferred).
- Phase 4 PSD2 SCA exemption table branch:
  `phase-4-psd2-sca-exemption-table` (deferred).

The cohort packages (5-of-5) ship complete; the domain packages ship
the contract surface + placeholder evaluators with R143 LOUD-ONCE-WARN
disclosure of the deferral.

---

## 5. R155 verdict + commit SHA discipline

Every claim in `reviews/MARATHON_2026-05-27/impl/M11_moneycheck_new_flagship.md`
cites the commit SHA + the `go test ./...` test receipt. R155 + R155.A
INDEX-LIE compliance: no claim of "Phase 2 wired" or "Phase 3 SAR filed"
will appear in the impl log; every Phase 1 scaffold claim is paired
with the on-disk artefact via `git show <sha> --stat`.

---

## 6. Cross-substrate parity (R151 KAT-1 cohort invariance)

`internal/lore/kat1.go` pins the cohort-canonical KAT-1 hex
`239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca`.
Reproducible via OpenSSL:

```
printf '\x01' > /tmp/kat1.bin
printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
# → HMAC-SHA256(stdin) = 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

This is the regulator-grade cold-verify gate that holds independently
of any cohort toolchain (FIPS PUB 180-4 + RFC 2104 + RFC 4648).

---

## 7. R175 production-wired Mirror-Mark (4/4 criteria from inception)

Per R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION:

1. **Production-traffic emit-path:**
   `internal/audit_ledger/ledger.go` Emit() calls `marker.Sign()` on
   every entry (non-test code).
2. **Cold-verify path:** OpenSSL one-liner reproduces the cohort
   canonical KAT-1 hex per `internal/lore/kat1.go` doc-comment.
3. **Boot-time R143 LOUD-ONCE-WARN:** when the marker is absent, the
   `MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED` advisory fires
   (Phase 2 deferred placeholder) AND a sibling R143 advisory disclosed
   from `internal/honest/CanonicalAdvisories()`.
4. **Cohort canonical KAT-1 hex pin:** pinned in
   `internal/lore/kat1.go` constant + `internal/firewall/firewall_test.go`
   firewall test.

---

## 8. Privacy + data-protection posture

moneycheck is a regulator-grade infrastructure library. It handles
financial transaction metadata + counterparty identity claims; under UK
GDPR Article 6(1)(c) the lawful basis for processing is compliance with
the PSR 2017 reimbursement-disposition obligation + POCA §330 SAR-
filing obligation. Both are statutory.

No data subject access request (DSAR) surface is implemented in Phase
1; Phase 4 wires the Article-15 DSAR export via cohort-canonical
mirror-mark stamping per the folio + ledger + casino cohort pattern.
