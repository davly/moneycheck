package trust

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestClient_Decide_HappyPath confirms the FCA-envelope ships verbatim
// and the response is parsed end-to-end.
func TestClient_Decide_HappyPath(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/escape" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %q", r.Method)
		}

		var got EscapeRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("server: decode body: %v", err)
		}

		if got.AuditEnvelope.ReviewerClass != ReviewerClassFCA {
			t.Errorf("reviewer_class = %q, want %q",
				got.AuditEnvelope.ReviewerClass, ReviewerClassFCA)
		}
		if got.AuditEnvelope.StatutoryRef != StatutoryRefFCAConsumerDuty {
			t.Errorf("statutory_ref = %q, want %q",
				got.AuditEnvelope.StatutoryRef, StatutoryRefFCAConsumerDuty)
		}
		if got.AuditEnvelope.Jurisdiction != "UK_FCA" {
			t.Errorf("jurisdiction = %q, want UK_FCA",
				got.AuditEnvelope.Jurisdiction)
		}
		if got.AuditEnvelope.CohortRole != CohortRoleMoneycheck {
			t.Errorf("cohort_role = %q, want %q",
				got.AuditEnvelope.CohortRole, CohortRoleMoneycheck)
		}

		resp := EscapeResponse{
			Verdict:       "escape",
			Score:         0.78,
			Factors:       FactorScores{Novelty: 0.7, Staleness: 0.8, ContextMismatch: 0.85, QualityDecay: 0.75},
			AuditEnvelope: got.AuditEnvelope,
			MirrorMark:    "lore@v1:test-mark-moneycheck",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 2*time.Second)
	req := EscapeRequest{
		SituationHash:  "moneycheck-sca-001",
		CurrentContext: "psd2_sca_exemption:low_value",
		AuditEnvelope:  FCAEnvelope("UK_FCA"),
	}

	resp, err := c.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if resp.Verdict != "escape" {
		t.Errorf("Verdict = %q, want escape", resp.Verdict)
	}
	if resp.MirrorMark != "lore@v1:test-mark-moneycheck" {
		t.Errorf("MirrorMark = %q, want test mark", resp.MirrorMark)
	}
}

// TestClient_Decide_FailClosed_ServerError confirms R175 — when
// escape-service returns 5xx, the LOCAL SCAEscapeGate decision must
// stand (surfaced via ErrEscapeServiceUnreachable).
func TestClient_Decide_FailClosed_ServerError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "synthetic outage", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 500*time.Millisecond)
	_, err := c.Decide(context.Background(), EscapeRequest{
		SituationHash: "moneycheck-sca-fail",
		AuditEnvelope: FCAEnvelope("UK_FCA"),
	})
	if err == nil {
		t.Fatal("expected error on 5xx, got nil — R175 fail-closed violated")
	}
	if !errors.Is(err, ErrEscapeServiceUnreachable) {
		t.Errorf("err = %v, want ErrEscapeServiceUnreachable", err)
	}
}

// TestClient_Decide_FailClosed_EmptyMark covers the 2xx-with-empty-mark
// edge — the upstream sign step failed; treat as fail-closed.
func TestClient_Decide_FailClosed_EmptyMark(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"verdict":"escape","score":0.9,"mirror_mark":""}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 500*time.Millisecond)
	_, err := c.Decide(context.Background(), EscapeRequest{
		SituationHash: "moneycheck-sca-empty-mark",
		AuditEnvelope: FCAEnvelope("UK_FCA"),
	})
	if err == nil {
		t.Fatal("expected error on empty mark, got nil")
	}
	if !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("err = %v, want ErrInvalidResponse", err)
	}
}

// TestFCAEnvelope_PopulatesDiscriminators pins the canonical FCA
// discriminators verbatim — change-detector test for the wire literals.
func TestFCAEnvelope_PopulatesDiscriminators(t *testing.T) {
	t.Parallel()

	env := FCAEnvelope("UK_FCA")
	if env.ReviewerClass != ReviewerClassFCA {
		t.Errorf("ReviewerClass = %q, want %q", env.ReviewerClass, ReviewerClassFCA)
	}
	if env.StatutoryRef != StatutoryRefFCAConsumerDuty {
		t.Errorf("StatutoryRef = %q, want %q", env.StatutoryRef, StatutoryRefFCAConsumerDuty)
	}
	if env.Jurisdiction != "UK_FCA" {
		t.Errorf("Jurisdiction = %q, want UK_FCA", env.Jurisdiction)
	}
	if env.CohortRole != CohortRoleMoneycheck {
		t.Errorf("CohortRole = %q, want %q", env.CohortRole, CohortRoleMoneycheck)
	}
	if strings.TrimSpace(env.LastReviewed) == "" {
		t.Error("LastReviewed must be non-empty (escape-service rejects)")
	}
	if _, err := time.Parse(time.RFC3339, env.LastReviewed); err != nil {
		t.Errorf("LastReviewed not RFC3339: %v", err)
	}
}
