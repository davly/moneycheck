// Package trust is the thin escape-service HTTP-client wrapper used by
// moneycheck to externalise trust-boundary decisions to the
// cohort-canonical escape-service primitive
// (`infrastructure/escape-service/` at R174 5-of-5 STRICT). Sibling of
// counsel/internal/trust + trial-ledger/internal/trust (R150
// R-PARALLEL-MAP).
//
// Why this exists (per IMP-T2-12 Phase 2):
//
//	Moneycheck's existing R153-shape SCA-escape gate lives in
//	`internal/psr_app_fraud/psr.go` SCAEscapeGate + Decide. That LOCAL
//	gate is load-bearing for the regulatory invariant ("any non-None
//	PSD2 SCA exemption → escape to human"). This package adds an
//	OPTIONAL EXTERNAL wire: when moneycheck emits an escape verdict,
//	it can POST the decision context to escape-service for AuditEnvelope
//	+ L43 Mirror-Mark stamping. The stamp lands in the firm's evidence
//	pack so an FCA-investigator can cold-verify the trust-boundary
//	trace via `lore-mark-verify`.
//
// Fail-closed discipline (R175 R-LOAD-BEARING-IN-PRODUCTION):
//
//	If escape-service is unreachable / returns 5xx / returns malformed
//	JSON, this client returns (nil, err). Callers MUST treat err as
//	"the LOCAL SCAEscapeGate result stands, but the EXTERNAL audit
//	stamp did NOT land in the evidence pack" — they MUST NOT fall back
//	to a non-escape disposition. The LOCAL gate remains load-bearing;
//	the wire is for evidence-pack stamping, not gate-bypass.
//
// Cohort role: moneycheck is the FCA-jurisdiction adopter of
// escape-service. Sibling adopters: counsel (SRA), trial-ledger (MHRA).
// All three pass the same wire shape with flagship-specific
// reviewer_class + statutory_ref + jurisdiction.
package trust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Reviewer-class + statutory-ref constants for moneycheck's
// FCA-jurisdiction adoption. LOAD-BEARING literals.
const (
	// ReviewerClassFCA names the FCA Consumer-Duty reviewer
	// attestation lineage. Maps to escape-service's HUMAN_ATTESTED
	// canonical class for in-firm review.
	ReviewerClassFCA = "HUMAN_ATTESTED"

	// StatutoryRefFCAConsumerDuty names the FCA PRIN 2A.2.21R(2)
	// consumer-duty clause that justifies the external-audit stamp
	// for moneycheck's recommendation trust-boundary decisions.
	StatutoryRefFCAConsumerDuty = "FCA PRIN 2A.2.21R(2)"

	// CohortRoleMoneycheck names moneycheck's cohort role in the
	// escape-service audit-row.
	CohortRoleMoneycheck = "moneycheck-trust-boundary-fca-jurisdiction"
)

// EscapeRequest is the wire shape moneycheck POSTs to escape-service.
type EscapeRequest struct {
	SituationHash      string        `json:"situation_hash"`
	CurrentContext     string        `json:"current_context"`
	ObservationHistory []Observation `json:"observation_history"`
	AuditEnvelope      AuditEnvelope `json:"audit_envelope"`
}

// Observation mirrors escape-service's escape.Observation wire shape.
type Observation struct {
	Hash      string  `json:"hash"`
	Timestamp int64   `json:"timestamp"`
	Quality   float64 `json:"quality"`
	Context   string  `json:"context"`
}

// AuditEnvelope is the R150 5-field review-metadata envelope.
type AuditEnvelope struct {
	ReviewerClass string `json:"reviewer_class"`
	StatutoryRef  string `json:"statutory_ref"`
	Jurisdiction  string `json:"jurisdiction"`
	CohortRole    string `json:"cohort_role"`
	LastReviewed  string `json:"last_reviewed"`
}

// EscapeResponse is the wire shape escape-service returns.
type EscapeResponse struct {
	Verdict       string        `json:"verdict"`
	Score         float64       `json:"score"`
	Factors       FactorScores  `json:"factors"`
	AuditEnvelope AuditEnvelope `json:"audit_envelope"`
	MirrorMark    string        `json:"mirror_mark"`
}

// FactorScores mirrors escape-service's escape.FactorScores wire shape.
type FactorScores struct {
	Novelty         float64 `json:"novelty"`
	Staleness       float64 `json:"staleness"`
	ContextMismatch float64 `json:"context_mismatch"`
	QualityDecay    float64 `json:"quality_decay"`
}

// Client is the escape-service HTTP wrapper. Safe for concurrent use.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient constructs an escape-service Client. timeout zero defaults
// to 5s. Set lower for transaction-decision call-sites.
func NewClient(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// ErrEscapeServiceUnreachable signals fail-closed — the LOCAL
// SCAEscapeGate decision stands; the evidence-pack stamp did NOT land.
var ErrEscapeServiceUnreachable = errors.New("trust: escape-service unreachable; LOCAL SCAEscapeGate decision stands, evidence-pack stamp NOT landed")

// ErrInvalidResponse signals fail-closed — escape-service 2xx response
// could not be parsed or is missing required fields.
var ErrInvalidResponse = errors.New("trust: escape-service returned malformed response; LOCAL SCAEscapeGate decision stands, evidence-pack stamp NOT landed")

// Decide POSTs the escape request to escape-service's `/v1/escape`
// endpoint. Fail-closed per R175 — see ErrEscapeServiceUnreachable.
func (c *Client) Decide(ctx context.Context, req EscapeRequest) (*EscapeResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil client", ErrEscapeServiceUnreachable)
	}
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, fmt.Errorf("%w: empty baseURL", ErrEscapeServiceUnreachable)
	}

	if strings.TrimSpace(req.AuditEnvelope.LastReviewed) == "" {
		req.AuditEnvelope.LastReviewed = time.Now().UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(req.AuditEnvelope.CohortRole) == "" {
		req.AuditEnvelope.CohortRole = CohortRoleMoneycheck
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal: %v", ErrEscapeServiceUnreachable, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/v1/escape", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: new request: %v", ErrEscapeServiceUnreachable, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: do: %v", ErrEscapeServiceUnreachable, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrEscapeServiceUnreachable, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status %d body %s",
			ErrEscapeServiceUnreachable, resp.StatusCode, string(respBody))
	}

	var out EscapeResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if strings.TrimSpace(out.MirrorMark) == "" {
		return nil, fmt.Errorf("%w: empty mirror_mark", ErrInvalidResponse)
	}

	return &out, nil
}

// FCAEnvelope returns a pre-populated AuditEnvelope for moneycheck's
// FCA-jurisdiction adoption. jurisdiction is typically "UK_FCA" — pass
// the regional firm code if a tenant needs finer-grained provenance.
func FCAEnvelope(jurisdiction string) AuditEnvelope {
	return AuditEnvelope{
		ReviewerClass: ReviewerClassFCA,
		StatutoryRef:  StatutoryRefFCAConsumerDuty,
		Jurisdiction:  jurisdiction,
		CohortRole:    CohortRoleMoneycheck,
		LastReviewed:  time.Now().UTC().Format(time.RFC3339),
	}
}
