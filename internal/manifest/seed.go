package manifest

import "time"

// PhaseOneShipDate is the wall-clock UTC date of the moneycheck Phase
// 1 inception ship (2026-05-27).
var PhaseOneShipDate = time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)

// Seed returns the canonical manifest inventory for moneycheck's
// curated regulatory-regime surface. Per CONTEXT.md §2 + §3:
//
//   - 5 RegRegime entries (PSR_2017 + PSR_2024_AMENDMENT + POCA_330 +
//     FCA_COBS_4 + PSD2_SCA_RTS)
//   - 3 SARFilingChannel entries (NCA_SAR_ONLINE + NCA_BULK_REPORT +
//     FCA_CONNECT_FORM)
//   - 4 SCAExemption entries (LOW_VALUE + TRUSTED_BENEFICIARY +
//     RECURRING + CORPORATE)
//   - 1 CounselReview placeholder entry (Phase 1 scaffold)
//
// = 13 entries total.
//
// Order is canonical (matches the regime composition order in
// internal/psr_app_fraud + internal/aml_sar).
func Seed() Manifest {
	return Manifest{
		// --- RegRegime entries (5) — anchored to UK SI + Acts ---

		{
			Key:               "PSR_2017",
			Class:             ClassRegRegime,
			Source:            SourceUKStatutoryInstrument,
			FreshAt:           PhaseOneShipDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			Rationale:         "Payment Services Regulations 2017, UK SI 2017/752. The substantive UK PSP regulatory regime under which moneycheck operates. Implements PSD2 in UK law post-2018; the 2024 amendment grafts the APP-fraud reimbursement obligation onto regulation 90+.",
			ReviewedByCounsel: false,
		},
		{
			Key:               "PSR_2024_AMENDMENT",
			Class:             ClassRegRegime,
			Source:            SourceUKStatutoryInstrument,
			FreshAt:           PhaseOneShipDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			Rationale:         "Payment Services (Amendment) Regulations 2024 — the mandatory APP-fraud reimbursement regime that took effect October 2024. Establishes 5-business-day reimbursement obligation + two named exception categories (gross-negligence + first-party-fraud). The Phase 2 evaluator lives behind MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED.",
			ReviewedByCounsel: false,
		},
		{
			Key:               "POCA_330",
			Class:             ClassRegRegime,
			Source:            SourceUKPrimaryLegislation,
			FreshAt:           PhaseOneShipDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			Rationale:         "Proceeds of Crime Act 2002 §330 — the SAR-filing obligation for the regulated sector. Failure to file is a criminal offence with up to 5 years' imprisonment + unlimited fine. The Phase 3 NCA envelope encoder lives behind MONEYCHECK_AML_SAR_FILING_PLACEHOLDER.",
			ReviewedByCounsel: false,
		},
		{
			Key:               "FCA_COBS_4",
			Class:             ClassRegRegime,
			Source:            SourceFCARulebook,
			FreshAt:           PhaseOneShipDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			Rationale:         "FCA Conduct of Business Sourcebook chapter 4 — customer-communication standards (clear / fair / not misleading) for risk disclosure. The disclosure renderer (Phase 4) lives behind MONEYCHECK_FCA_CRD_4_DISCLOSURE_REQUIRED. Confidence is Medium because the rulebook chapter is derived from FSMA 2000 secondary delegated authority + FCA practitioner notes; primary-source confidence requires counsel review.",
			ReviewedByCounsel: false,
		},
		{
			Key:               "PSD2_SCA_RTS",
			Class:             ClassRegRegime,
			Source:            SourceEUDelegatedRegulation,
			FreshAt:           PhaseOneShipDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			Rationale:         "Commission Delegated Regulation (EU) 2018/389 — the regulatory technical standard on Strong Customer Authentication under PSD2 article 98. Defines the closed list of SCA exemptions. The Phase 4 exemption table lives behind MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT (R153 saturator).",
			ReviewedByCounsel: false,
		},

		// --- SARFilingChannel entries (3) — anchored to NCA guidance ---

		{
			Key:               "NCA_SAR_ONLINE",
			Class:             ClassSARFilingChannel,
			Source:            SourceNCAGuidance,
			FreshAt:           PhaseOneShipDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			Rationale:         "National Crime Agency SAR Online v2 web form — the canonical electronic submission channel. Phase 3 wires the XML envelope encoder; until then SAR candidates are informational only.",
			ReviewedByCounsel: false,
		},
		{
			Key:               "NCA_BULK_REPORT",
			Class:             ClassSARFilingChannel,
			Source:            SourceNCAGuidance,
			FreshAt:           PhaseOneShipDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			Rationale:         "NCA Bulk Report Submission API — for high-volume reporters (>1000 SARs/year). Phase 3+ enhancement; not required for Phase 1 scaffold.",
			ReviewedByCounsel: false,
		},
		{
			Key:               "FCA_CONNECT_FORM",
			Class:             ClassSARFilingChannel,
			Source:            SourceFCARulebook,
			FreshAt:           PhaseOneShipDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			Rationale:         "FCA Connect Form — for prudential / supervisory notification of significant SAR-related events (alongside the NCA filing). Phase 3+ enhancement.",
			ReviewedByCounsel: false,
		},

		// --- SCAExemption entries (4) — anchored to PSD2 RTS ---

		{
			Key:               "SCA_LOW_VALUE",
			Class:             ClassSCAExemption,
			Source:            SourceEUDelegatedRegulation,
			FreshAt:           PhaseOneShipDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			Rationale:         "PSD2 RTS Article 16 — low-value transaction exemption. Currently €30/transaction + €100/cumulative-since-last-SCA. Phase 4 wires the exemption-table evaluator; Phase 1 always escapes to human review per R153.",
			ReviewedByCounsel: false,
		},
		{
			Key:               "SCA_TRUSTED_BENEFICIARY",
			Class:             ClassSCAExemption,
			Source:            SourceEUDelegatedRegulation,
			FreshAt:           PhaseOneShipDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			Rationale:         "PSD2 RTS Article 13 — trusted beneficiary exemption (payer added beneficiary to whitelist using SCA). Phase 4 wires the whitelist-lookup; Phase 1 always escapes per R153.",
			ReviewedByCounsel: false,
		},
		{
			Key:               "SCA_RECURRING",
			Class:             ClassSCAExemption,
			Source:            SourceEUDelegatedRegulation,
			FreshAt:           PhaseOneShipDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			Rationale:         "PSD2 RTS Article 14 — recurring transaction exemption (same amount + same payee as previous SCA-authenticated transaction). Phase 4 wires the recurrence-detector; Phase 1 always escapes per R153.",
			ReviewedByCounsel: false,
		},
		{
			Key:               "SCA_CORPORATE",
			Class:             ClassSCAExemption,
			Source:            SourceEUDelegatedRegulation,
			FreshAt:           PhaseOneShipDate,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			Rationale:         "PSD2 RTS Article 17 — corporate-payment-process exemption (dedicated payment processes meeting prescribed security standards). Phase 4 wires the corporate-account classifier; Phase 1 always escapes per R153.",
			ReviewedByCounsel: false,
		},

		// --- CounselReview placeholder (1) — R150.E + R166 sibling ---

		{
			Key:               "PHASE_1_COUNSEL_REVIEW_PENDING",
			Class:             ClassCounselReview,
			Source:            SourcePhasePending,
			FreshAt:           SentinelHonestTODO,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHonestTODO,
			Rationale:         "Phase 1 scaffold disclosure: no entry in this manifest has been reviewed by counsel. The R166 LIABILITY-FOOTER-CONST sibling fires MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE on every disposition surface call. Phase 4 wires counsel-grade attestation per regime.",
			ReviewedByCounsel: false,
		},
	}
}
