# SECURITY — moneycheck

**Substrate:** Go 1.22, pure stdlib, zero external dependencies.

**Status:** Phase 1 MVP scaffold. Pre-production; **MUST NOT be used as
the sole basis for a real PSR APP-fraud reimbursement decision or a
real NCA SAR filing**. Both surfaces are placeholder-mode by design;
the R143 LOUD-ONCE-WARN advisories fire as the canonical signal of
deferred-Phase status.

---

## Threat model summary

moneycheck is a **regulator-grade infrastructure library**. It assumes:

- A trusted operator (the PSP using the library).
- An adversarial counterparty (the APP-fraud perpetrator) whose
  attack surface is the payment-rail integration, NOT the moneycheck
  library itself.
- An untrusted downstream (an FCA / NCA regulator running cold-verify
  against an emitted audit-ledger row using only `(corpus, payload,
  key)`).

---

## Patterns intentionally absent

Per Phase 1 scaffold scope:

1. **No PII persistence in moneycheck itself.** The library is
   stateless; the audit-ledger emits over an in-memory sink in Phase
   1, persisted via a host-provided sink in Phase 2+.
2. **No database substrate (`database/sql` / sqlite / postgres).**
   The Go layer is stateless. Host PSP integrations provide the
   persistent ledger.
3. **No HTTP listener.** moneycheck is a library + CLI, not a daemon.
4. **No HTTP outbound client.** The NCA SAR-Online envelope encoder
   (Phase 3) will live on its own R145.B branch with its own outbound
   HTTP surface.
5. **No auth / identity primitives** (no JWT / bcrypt / pbkdf2 /
   crypto/tls). Phase 1 scaffold is offline; Phase 2+ host integrations
   provide auth.
6. **No PII / no biometrics / no face recognition.** moneycheck operates
   on financial transaction metadata + counterparty identity claims
   per UK GDPR Article 6(1)(c) statutory-basis processing.
7. **No environment-variable reads** in the cohort + domain packages.
   `cmd/moneycheck/main.go` may read env vars for CLI config; the
   library packages do not.
8. **No external dependencies.** `go.mod` is stdlib-only; the R145.C
   firewall pins `TestFirewall_NoExternalDeps` to enforce this.

---

## Trust boundaries

1. **`internal/mirrormark/`** — the L43 Mirror-Mark v1 signer. Trust
   boundary between the PSP-internal audit ledger and the downstream
   regulator's cold-verify path. The HMAC key is the operator's
   `iik_` key; cold-verify holds without the host filesystem.
2. **`internal/psr_app_fraud/`** — the PSR APP reimbursement
   disposition surface. Phase 1 emits placeholder dispositions; Phase
   2 wires the real PSR 2024 eligibility tree. The R143 LOUD-ONCE-WARN
   advisory `MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED`
   surfaces the placeholder mode.
3. **`internal/aml_sar/`** — the SAR-filing placeholder. Phase 1 emits
   SAR candidates; Phase 3 wires the NCA SAR-Online v2 envelope. The
   R143 LOUD-ONCE-WARN advisory `MONEYCHECK_AML_SAR_FILING_PLACEHOLDER`
   surfaces the placeholder mode.
4. **`internal/audit_ledger/`** — the append-only audit ledger
   (production-wired Mirror-Mark stamping). This is the load-bearing
   trust boundary: every entry is signed in Phase 1, even though the
   PSR + AML surfaces are placeholder. The regulator cold-verify path
   is real.

---

## Patterns honest about deferral

The MVP scaffold is honest about every load-bearing surface that is
not yet wired:

| Phase 1 surface | Phase deferral | R143 advisory |
|---|---|---|
| PSR APP reimbursement disposition | Phase 2 evaluator wiring | `MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED` (Error) |
| AML SAR NCA envelope | Phase 3 NCA SAR-Online v2 encoder | `MONEYCHECK_AML_SAR_FILING_PLACEHOLDER` (Error) |
| FCA COBS 4 disclosure rendering | Phase 4 counsel review | `MONEYCHECK_FCA_CRD_4_DISCLOSURE_REQUIRED` (Warn) |
| PSD2 SCA escape gate | Phase 4 exemption table | `MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT` (Error — R153 saturator) |
| Public API disposition surface | Counsel review (R166) | `MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE` (Warn) |

---

## Cohort cross-substrate parity (R151 + R175)

The KAT-1 HMAC-SHA256 hex
`239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca`
is byte-identical to the cohort canonical anchor pinned across the
~30+ cohort flagships (anchor + folio + insights + casino + ledger + …).
A regulator with `openssl dgst` and this hex string can reproduce the
digest from canonical inputs WITHOUT any Limitless toolchain.

The Mirror-Mark v1 wire format (`lore@v1:` prefix + 8-byte corpus
prefix + 32-byte HMAC) is byte-identical to the cohort canonical signer
(`foundation/pkg/mirrormark/StdlibMarker`). The `internal/mirrormark/`
package re-implements the signer in-process per the R174 5-of-5
canonical reference shape; future R145.B branching may thin-shim
re-export `foundation/pkg/mirrormark` once the foundation package is
fully published.

---

## Reporting

Email: `david@vocala.co` (RFC2350 contact for moneycheck-specific
security findings).
