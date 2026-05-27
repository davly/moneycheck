package lore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestKAT1DigestLiteral pins the cohort-canonical hex literal as an
// immutable string constant. Any drift on this byte sequence breaks
// the cohort cross-substrate parity gate.
func TestKAT1DigestLiteral(t *testing.T) {
	want := "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"
	if KAT1Digest != want {
		t.Errorf("KAT1Digest = %q, want %q (cohort cross-substrate parity broken)", KAT1Digest, want)
	}
	if len(KAT1Digest) != 64 {
		t.Errorf("KAT1Digest length = %d, want 64 (hex-encoded SHA-256)", len(KAT1Digest))
	}
}

// TestKAT1InputCanonical pins the canonical input bytes (0x01 || 32×0x00)
// + total length of 33 bytes.
func TestKAT1InputCanonical(t *testing.T) {
	got := KAT1Input()
	if len(got) != 33 {
		t.Fatalf("KAT1Input length = %d, want 33", len(got))
	}
	if got[0] != 0x01 {
		t.Errorf("KAT1Input[0] = 0x%02x, want 0x01", got[0])
	}
	for i := 1; i < 33; i++ {
		if got[i] != 0x00 {
			t.Errorf("KAT1Input[%d] = 0x%02x, want 0x00", i, got[i])
		}
	}
}

// TestComputeKAT1ReproducesDigest verifies that ComputeKAT1() returns
// exactly KAT1Digest. Re-derives the digest independently inline (via
// raw stdlib hmac.New + crypto/sha256) so the test is a dual-drift
// firewall: if ComputeKAT1 silently changes, this still pins the
// canonical computation.
//
// R145.C FIREWALL-TEST-DISCIPLINE: this test re-derives the KAT-1
// vector inline rather than calling ComputeKAT1() and trusting its
// output — verify-not-inherit per godfather memory.
func TestComputeKAT1ReproducesDigest(t *testing.T) {
	// Inline re-derivation (verify-not-inherit, R145.C).
	mac := hmac.New(sha256.New, []byte{})
	mac.Write([]byte{0x01})
	mac.Write(make([]byte, 32))
	wantHex := hex.EncodeToString(mac.Sum(nil))

	// Canonical-literal pin.
	if wantHex != KAT1Digest {
		t.Errorf("inline re-derivation = %q, KAT1Digest = %q — drift between literal and inline recompute", wantHex, KAT1Digest)
	}

	// Library entry-point pin.
	got := ComputeKAT1()
	if got != KAT1Digest {
		t.Errorf("ComputeKAT1() = %q, KAT1Digest = %q", got, KAT1Digest)
	}
	if got != wantHex {
		t.Errorf("ComputeKAT1() = %q, inline re-derivation = %q", got, wantHex)
	}
}

// TestVerifyKAT1Pass pins that VerifyKAT1 returns nil under canonical
// inputs (the happy path that gates regulator-pre-flight).
func TestVerifyKAT1Pass(t *testing.T) {
	if err := VerifyKAT1(); err != nil {
		t.Errorf("VerifyKAT1 returned %v, want nil", err)
	}
}

// TestKATMismatchErrorShape pins that KATMismatchError surfaces the
// Vector / Computed / Expected triple so a forensic operator can
// diagnose drift without re-running the recipe.
func TestKATMismatchErrorShape(t *testing.T) {
	e := &KATMismatchError{
		Vector:   "KAT-1",
		Computed: "deadbeef",
		Expected: "239a7d0d",
	}
	msg := e.Error()
	wantSubstrs := []string{"moneycheck/lore", "KAT-1", "deadbeef", "239a7d0d"}
	for _, sub := range wantSubstrs {
		if !contains(msg, sub) {
			t.Errorf("KATMismatchError.Error() = %q, want substring %q", msg, sub)
		}
	}
}

// contains is a stdlib-only substring check (avoids strings import in
// this test file to keep dependency surface minimal).
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
