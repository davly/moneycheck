# ARCHITECTURE — moneycheck

**Substrate:** Go 1.22, pure stdlib, zero external dependencies.

**Cohort posture:** R174 5-of-5 cohort maturity FROM INCEPTION.

---

## 1. Big picture

moneycheck composes three UK financial-services regulatory regimes
into a single Go library + CLI:

```
                    +---- internal/audit_ledger ----+
                    |  (Mirror-Mark v1 wired emit)  |
                    +-------+------+----------+-----+
                            ^      ^          ^
                            |      |          |
+------------ internal/psr_app_fraud -------+  |
| PSR 2017 + PSR (Amendment) 2024           |  |
| APP reimbursement disposition + SCA gate  |  |
+------------------+-------+----------------+  |
                   |       |                   |
                   v       v                   |
            +------+-------+------+            |
            |  internal/aml_sar   |            |
            |  POCA §330 SAR      +------------+
            |  filing placeholder |
            +------+-------+------+
                   |       |
                   v       v
            +------+-------+--------+
            |  cmd/moneycheck       |
            |  CLI surface          |
            +-----------------------+
```

Five cohort packages (`firewall/lore/mirrormark/manifest/honest/`) are
the R174 5-of-5 maturity ladder. Three domain packages
(`psr_app_fraud/aml_sar/audit_ledger/`) compose the regulatory
disposition + filing + ledger surface.

---

## 2. Mirror-Mark wired from inception (R175)

The load-bearing architectural choice: **every audit-ledger emit is
Mirror-Mark stamped from Phase 1**, even though the PSR + AML surfaces
are placeholder-mode.

```go
func (l *Ledger) Emit(entry Entry) Entry {
    // Compute Mirror-Mark over canonical body (with mark cleared)
    entry.MirrorMark = ""
    body, _ := json.Marshal(entry)
    entry.MirrorMark = l.marker.Sign(body)
    l.entries = append(l.entries, entry)
    return entry
}
```

A regulator holding `(lore.tar.gz, entry-bytes-with-mark-cleared,
the PSP's iik_ key)` can re-derive the mark via
`internal/mirrormark/Verify` and confirm the PSP emitted exactly these
bytes.

R175 4/4 criteria from inception:

1. **Production-traffic emit-path:** ✓ `internal/audit_ledger/ledger.go`
   `Emit()` is non-test code; grep finds the `marker.Sign()` call.
2. **Cold-verify path:** ✓ OpenSSL one-liner reproduces KAT-1 hex.
3. **Boot-time R143 LOUD-ONCE-WARN:** ✓ five named advisories disclose
   placeholder state of the PSR/AML/SCA/disclosure surfaces.
4. **Cohort canonical KAT-1 hex pin:** ✓ pinned in
   `internal/lore/kat1.go` + `internal/firewall/firewall_test.go`.

---

## 3. Phase deferral discipline (R176 LIBRARY-FIRST-WIRE-LATER)

Phase 1 ships the **library surface complete**; the **production-
domain wire-ins are explicitly deferred** to named R145.B branches:

- Phase 2: `phase-2-psr-app-reimbursement-evaluator`
- Phase 3: `phase-3-aml-sar-nca-envelope`
- Phase 4: `phase-4-psd2-sca-exemption-table`

Per R176, no Phase 1 ship will bundle a half-finished Phase 2 wire-in.
The R143 LOUD-ONCE-WARN advisories are the runtime disclosure.

---

## 4. R153 LIFE_SAFETY_ESCAPE_INVARIANT — PSD2 SCA escape gate

The SCA escape gate is the moneycheck instantiation of R153
R-DOMAIN-ESCAPE-INVARIANT (the life-safety + regulator-strict-liability
saturator class). The principle: **when SCA cannot be confidently
authorised, refuse to decide and escape to a human reviewer**.

The disposition surface (`internal/psr_app_fraud/Disposition`) names
the closed-set verdict enum:

```
DispositionReimburse        // Phase 2: PSR-eligible
DispositionDeny             // Phase 2: PSR-named-exception applies
DispositionEscapeToHuman    // R153: refuse-to-decide
DispositionPlaceholder      // Phase 1: scaffold-mode
```

Phase 1 always returns `DispositionPlaceholder` + fires the R143
`MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED` advisory.

When the SCA escape gate triggers (an SCA-exemption claim cannot be
validated against the Phase 4 exemption table), the disposition is
`DispositionEscapeToHuman` + the R143
`MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT` advisory fires.

---

## 5. R150 PARALLEL-MAP review-metadata envelope

The `internal/manifest/` package ships the canonical 5-field
review-metadata envelope (per R150 cohort canonical shape):

```go
type Entry struct {
    Key           string
    Class         Class     // RegRegime / SARFilingChannel / SCAExemption / CounselReview
    Source        Source    // closed enum
    FreshAt       time.Time
    SchemaVersion int
    Confidence    Confidence
    Rationale     string
}
```

Plus the R150.D `IsStale()` 9-path check + R150.E `ReviewedByCounsel`
field-7 extension for regulator-grade disclosure attestation. The
manifest catalogues the regulatory regimes moneycheck implements
(PSR / POCA / FCA / PSD2) + their counsel-review attestation status.

---

## 6. R166 LIABILITY-FOOTER-CONST sibling

The disposition rendering surface (`cmd/moneycheck`) appends the
R166 LIABILITY-FOOTER-CONST footer to every output, with
`ReviewedByCounsel=false` rendered explicitly. The R143
`MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE` advisory fires per process to
surface the deferral.

---

## 7. Hash-only audit-ledger emit (no payment-rail integration)

Phase 1 audit-ledger emits to an **in-memory sink** only; no payment-
rail integration, no NCA submission, no FCA filing. The library is
**hash-only** in the cross-pollination sense: the Mirror-Mark
fingerprint is the load-bearing artefact. A future Phase host PSP
integration will wire the in-memory sink to a real Bolt / Postgres
audit-ledger and (separately) wire the NCA / FCA filing channels.
