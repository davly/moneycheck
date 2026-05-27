// Package manifest — R150 PARALLEL-MAP-R144-REVIEW-METADATA register
// for moneycheck's curated regulatory-regime surface.
//
// 2026-05-27 new-flagship-inception ship. Pure-stdlib; zero deps.
// Ships the canonical 5-field schematised-knowledge envelope
// (FreshAt / Source / IsStale / SchemaVersion / Confidence) over
// moneycheck's curated regulatory-regime catalogue (PSR 2017 + PSR
// (Amendment) 2024 / POCA §330 / FCA COBS 4 / PSD2 SCA RTS). Honest-
// TODO sentinels for entries pending counsel review (R150.E
// ReviewedByCounsel field-7 extension).
//
// R150 promotion (godfather memory 2026-05-22, R144 sub-class):
// Class 1 schematised-knowledge cohort saturated 11/3 across 12
// instances. moneycheck joins as a new instance — the UK regulatory-
// compliance Go library with curated PSR + POCA + FCA + PSD2 regime
// catalogue anchored to public-domain regulatory citations.
//
// Canonical 5-field shape (+ R150.E field-7 extension for counsel-
// review attestation):
//
//	type Entry struct {
//	    Key                  string
//	    Class                Class      // closed enum
//	    Source               Source     // closed enum, NOT free-form
//	    FreshAt              time.Time  // when source was last verified
//	    SchemaVersion        int        // pinned at v1
//	    Confidence           Confidence // closed 3-state
//	    Rationale            string     // forensic-readability aid
//	    ReviewedByCounsel    bool       // R150.E sub-clause + R166 sibling
//	}
//
// 9-path IsStale (per godfather R150 canonical shape).
//
// moneycheck's curated regulatory catalogue (current inventory):
//   - 4 RegRegime entries (PSR_2017 + PSR_2024_AMENDMENT + POCA_330 + FCA_COBS_4 + PSD2_SCA_RTS)
//   - 3 SARFilingChannel entries (NCA_SAR_ONLINE + NCA_BULK_REPORT + FCA_CONNECT_FORM)
//   - 4 SCAExemption entries (LOW_VALUE + TRUSTED_BENEFICIARY + RECURRING + CORPORATE)
//   - 1 CounselReview entry (Phase 1 placeholder)
package manifest

import "time"

// SchemaVersion is the canonical schema version for moneycheck's
// Manifest entries. Pinned at v1 per godfather R150 canonical shape;
// bumping invalidates every entry — coordinate with cohort.
const SchemaVersion = 1

// SentinelHonestTODO is the canonical zero-time sentinel for entries
// whose FreshAt is unknown or pending. Per godfather R150 canonical
// shape: 1970-01-01 UTC = "honest-TODO — needs reviewer-class signoff".
var SentinelHonestTODO = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

// Source is the closed-set source-of-truth enum for Manifest entries.
// NOT free-form text. Each value is a cohort-recognised provenance
// shape with documented evidence boundary.
type Source int

const (
	// SourceUnknownHonestTODO is the sentinel for entries whose source
	// has not yet been documented. IsStale always returns true for
	// SourceUnknownHonestTODO entries.
	SourceUnknownHonestTODO Source = iota

	// SourceUKPrimaryLegislation — entry derived from UK primary
	// legislation (an Act of Parliament: e.g. POCA 2002, FSMA 2000).
	SourceUKPrimaryLegislation

	// SourceUKStatutoryInstrument — entry derived from UK secondary
	// legislation (a Statutory Instrument: e.g. PSR 2017 SI 2017/752,
	// MLR 2017 SI 2017/692).
	SourceUKStatutoryInstrument

	// SourceFCARulebook — entry derived from the FCA Handbook
	// (COBS / SYSC / SUP / DISP rulebook sections).
	SourceFCARulebook

	// SourceEUDelegatedRegulation — entry derived from an EU
	// Delegated Regulation (e.g. PSD2 RTS on SCA, Commission Delegated
	// Regulation (EU) 2018/389).
	SourceEUDelegatedRegulation

	// SourceNCAGuidance — entry derived from National Crime Agency
	// guidance (SAR Online v2 form structure, POCA §330 guidance).
	SourceNCAGuidance

	// SourceCounselReview — entry validated by external solicitors'
	// firm under regulator-strict-liability standard.
	SourceCounselReview

	// SourcePhasePending — entry depends on a not-yet-shipped Phase
	// (e.g. Phase 2 PSR reimbursement evaluator, Phase 3 NCA SAR
	// envelope). IsStale returns true until the Phase lands.
	SourcePhasePending
)

// String returns the canonical name for a Source.
func (s Source) String() string {
	switch s {
	case SourceUnknownHonestTODO:
		return "unknown_honest_todo"
	case SourceUKPrimaryLegislation:
		return "uk_primary_legislation"
	case SourceUKStatutoryInstrument:
		return "uk_statutory_instrument"
	case SourceFCARulebook:
		return "fca_rulebook"
	case SourceEUDelegatedRegulation:
		return "eu_delegated_regulation"
	case SourceNCAGuidance:
		return "nca_guidance"
	case SourceCounselReview:
		return "counsel_review"
	case SourcePhasePending:
		return "phase_pending"
	}
	return "unknown"
}

// Confidence is the closed-set tier label for entry confidence.
// 3-state per godfather R150 canonical shape: high / medium /
// honest_todo.
type Confidence int

const (
	// ConfidenceHonestTODO — confidence is not yet established; entry
	// requires qualified reviewer signoff. IsStale always true.
	ConfidenceHonestTODO Confidence = iota

	// ConfidenceMedium — confidence is partial (e.g. citation derived
	// from secondary source like an FCA guidance note rather than the
	// underlying primary legislation).
	ConfidenceMedium

	// ConfidenceHigh — confidence is full (canonical primary-source
	// citation, counsel-reviewed).
	ConfidenceHigh
)

// String returns the canonical name for a Confidence.
func (c Confidence) String() string {
	switch c {
	case ConfidenceHonestTODO:
		return "honest_todo"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceHigh:
		return "high"
	}
	return "unknown"
}

// Class is the canonical entry-class label so consumers can filter
// entries by curated content surface (RegRegime / SARFilingChannel /
// SCAExemption / CounselReview). Closed enum.
type Class int

const (
	// ClassRegRegime — a UK regulatory regime moneycheck implements
	// (PSR 2017, PSR 2024 Amendment, POCA §330, FCA COBS 4, PSD2 SCA RTS).
	ClassRegRegime Class = iota

	// ClassSARFilingChannel — a Suspicious Activity Report filing
	// channel (NCA SAR Online v2, NCA bulk-report, FCA Connect form).
	ClassSARFilingChannel

	// ClassSCAExemption — a PSD2 Strong Customer Authentication
	// exemption (low-value, trusted beneficiary, recurring beneficiary,
	// corporate).
	ClassSCAExemption

	// ClassCounselReview — counsel-review attestation surface
	// (R150.E + R166 LIABILITY-FOOTER-CONST sibling).
	ClassCounselReview
)

// String returns the canonical name for a Class.
func (cl Class) String() string {
	switch cl {
	case ClassRegRegime:
		return "reg_regime"
	case ClassSARFilingChannel:
		return "sar_filing_channel"
	case ClassSCAExemption:
		return "sca_exemption"
	case ClassCounselReview:
		return "counsel_review"
	}
	return "unknown"
}

// Entry is the canonical 5-field schematised-knowledge envelope plus
// R150.E ReviewedByCounsel field-7 extension. Per godfather R150
// canonical shape + R150.E sub-clause amendment.
type Entry struct {
	// Key is the unique identifier for this entry within its Class.
	// (Class + Key) is the manifest-wide composite key.
	Key string

	// Class identifies which curated content surface this entry
	// belongs to.
	Class Class

	// Source is the closed-set source-of-truth provenance enum.
	Source Source

	// FreshAt is the wall-clock UTC time the upstream source was
	// last verified by a qualified reviewer. Use SentinelHonestTODO
	// for entries whose freshness has never been established.
	FreshAt time.Time

	// SchemaVersion is the manifest-envelope schema version. Pinned
	// at v1 (manifest.SchemaVersion); bumping invalidates every
	// entry.
	SchemaVersion int

	// Confidence tier for this entry. ConfidenceHonestTODO marks
	// entries needing qualified-reviewer signoff.
	Confidence Confidence

	// Rationale carries a short human-readable note explaining the
	// source citation. NOT load-bearing for any code path — it's a
	// forensic-readability aid for the next reviewer.
	Rationale string

	// ReviewedByCounsel is the R150.E field-7 extension + R166
	// LIABILITY-FOOTER-CONST sibling. False by default (Phase 1
	// scaffold posture); true ONLY when an external solicitors' firm
	// has attested the entry under regulator-strict-liability standard.
	ReviewedByCounsel bool
}

// IsStale reports whether this entry is past its freshness window.
// Returns true if:
//
//   - Source == SourceUnknownHonestTODO
//   - Confidence == ConfidenceHonestTODO
//   - SchemaVersion != current SchemaVersion
//   - FreshAt is the SentinelHonestTODO zero-time
//   - now.Sub(FreshAt) > maxAge (only when maxAge > 0)
//
// 9-path IsStale (per godfather R150 canonical shape):
//
//	(1) SourceUnknownHonestTODO → true (no provenance)
//	(2) ConfidenceHonestTODO → true (no qualified signoff)
//	(3) SchemaVersion drift → true (envelope incompatible)
//	(4) FreshAt == SentinelHonestTODO → true (never verified)
//	(5) maxAge <= 0 + above clauses don't fire → false (age check off)
//	(6) FreshAt is zero-time (uninitialised) → true (defensive — same
//	    shape as SentinelHonestTODO)
//	(7) FreshAt in future (clock skew or bad data) → true (defensive)
//	(8) now.Sub(FreshAt) > maxAge → true (age exceeded)
//	(9) all clauses pass → false (entry fresh)
//
// The 9-path shape is the cohort-canonical R150 contract — every
// instance MUST cover the same 9 staleness routes.
func (e Entry) IsStale(now time.Time, maxAge time.Duration) bool {
	if e.Source == SourceUnknownHonestTODO {
		return true
	}
	if e.Confidence == ConfidenceHonestTODO {
		return true
	}
	if e.SchemaVersion != SchemaVersion {
		return true
	}
	if e.FreshAt.Equal(SentinelHonestTODO) {
		return true
	}
	if e.FreshAt.IsZero() {
		return true
	}
	if e.FreshAt.After(now) {
		return true // defensive — clock skew or bad data
	}
	if maxAge > 0 && now.Sub(e.FreshAt) > maxAge {
		return true
	}
	return false
}

// Manifest is the curated content surface inventory. Ordered;
// duplicates allowed only if (Class, Key) is unique.
type Manifest []Entry

// FindByKey returns the first Entry matching (class, key), or nil
// if none exists. Linear scan; manifest size is small (~12 entries)
// so no index needed.
func (m Manifest) FindByKey(class Class, key string) *Entry {
	for i, e := range m {
		if e.Class == class && e.Key == key {
			return &m[i]
		}
	}
	return nil
}

// HonestTODOCount returns the number of entries flagged as
// honest-TODO under either Source or Confidence. Surfaces the
// fraction of the manifest that still needs qualified-reviewer
// attention.
func (m Manifest) HonestTODOCount() int {
	n := 0
	for _, e := range m {
		if e.Source == SourceUnknownHonestTODO || e.Confidence == ConfidenceHonestTODO {
			n++
		}
	}
	return n
}

// StaleCount returns the number of entries IsStale would return
// true for at `now` against `maxAge`. O(n) over the manifest.
func (m Manifest) StaleCount(now time.Time, maxAge time.Duration) int {
	n := 0
	for _, e := range m {
		if e.IsStale(now, maxAge) {
			n++
		}
	}
	return n
}

// CounselReviewedCount returns the number of entries that carry
// ReviewedByCounsel=true (R150.E field-7 extension). Surfaces the
// fraction of the manifest that has counsel-grade attestation; Phase
// 1 expects 0 (placeholder mode).
func (m Manifest) CounselReviewedCount() int {
	n := 0
	for _, e := range m {
		if e.ReviewedByCounsel {
			n++
		}
	}
	return n
}
