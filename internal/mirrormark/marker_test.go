package mirrormark

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// TestMarkPrefixLiteral pins the cohort-canonical header-value prefix.
// Drift breaks downstream identification of v1 marks.
func TestMarkPrefixLiteral(t *testing.T) {
	if MarkPrefix != "lore@v1:" {
		t.Errorf("MarkPrefix = %q, want \"lore@v1:\"", MarkPrefix)
	}
}

// TestMarkBodyLenConstants pin the canonical body shape constants
// (8-byte corpus prefix + 32-byte HMAC = 40-byte body).
func TestMarkBodyLenConstants(t *testing.T) {
	if MarkCorpusPrefixLen != 8 {
		t.Errorf("MarkCorpusPrefixLen = %d, want 8", MarkCorpusPrefixLen)
	}
	if MarkBodyLen != 40 {
		t.Errorf("MarkBodyLen = %d, want 40 (8 + 32)", MarkBodyLen)
	}
	if sha256.Size != 32 {
		t.Errorf("sha256.Size = %d, want 32", sha256.Size)
	}
}

// TestSignRoundTrip pins the canonical Mirror-Mark v1 shape:
//
//	"lore@v1:" + base64url(corpusSHA[:8] || HMAC(0x01 || corpusSHA || payload, key))
//
// Re-derives the expected output inline (R145.C verify-not-inherit
// firewall) and compares against the library entry-point Sign().
func TestSignRoundTrip(t *testing.T) {
	var corpus [sha256.Size]byte
	for i := range corpus {
		corpus[i] = byte(i + 1) // 0x01..0x20
	}
	key := []byte("test-key-32-bytes-exactly--------")
	payload := []byte("hello, regulator")

	// Inline re-derivation (verify-not-inherit).
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte{0x01})
	mac.Write(corpus[:])
	mac.Write(payload)
	digest := mac.Sum(nil)
	body := append([]byte{}, corpus[:8]...)
	body = append(body, digest...)
	wantMark := "lore@v1:" + base64.RawURLEncoding.EncodeToString(body)

	gotMark := Sign(corpus, payload, key)
	if gotMark != wantMark {
		t.Errorf("Sign() = %q, want %q", gotMark, wantMark)
	}
	if !strings.HasPrefix(gotMark, "lore@v1:") {
		t.Errorf("Sign() output missing \"lore@v1:\" prefix: %q", gotMark)
	}
	// The base64url body is 54 chars (40 raw bytes → 54 base64url
	// chars without padding).
	bodyEncoded := strings.TrimPrefix(gotMark, "lore@v1:")
	if len(bodyEncoded) != 54 {
		t.Errorf("base64url body length = %d, want 54", len(bodyEncoded))
	}
}

// TestVerifyPass pins the happy path of Verify.
func TestVerifyPass(t *testing.T) {
	var corpus [sha256.Size]byte
	corpus[0] = 0x42
	key := []byte("test-key")
	payload := []byte("verify me")

	mark := Sign(corpus, payload, key)
	if err := Verify(corpus, payload, key, mark); err != nil {
		t.Errorf("Verify(canonical) = %v, want nil", err)
	}
}

// TestVerifyFailsOnTamper pins that tampered payload surfaces
// ErrMarkMismatch.
func TestVerifyFailsOnTamper(t *testing.T) {
	var corpus [sha256.Size]byte
	key := []byte("test-key")
	payload := []byte("original")

	mark := Sign(corpus, payload, key)
	tampered := []byte("tampered")
	if err := Verify(corpus, tampered, key, mark); err == nil {
		t.Errorf("Verify(tampered) = nil, want ErrMarkMismatch")
	} else if err != ErrMarkMismatch {
		t.Errorf("Verify(tampered) error = %v, want ErrMarkMismatch", err)
	}
}

// TestNewStdlibMarkerEmptyKey pins the fail-closed contract for empty
// keys.
func TestNewStdlibMarkerEmptyKey(t *testing.T) {
	var corpus [sha256.Size]byte
	_, err := NewStdlibMarker(corpus, []byte{})
	if err != ErrEmptyKey {
		t.Errorf("NewStdlibMarker(empty key) = %v, want ErrEmptyKey", err)
	}
}

// TestPlaceholderMarkerEmits pins that a placeholder marker can still
// emit syntactically valid marks (but UsingPlaceholder reports true).
func TestPlaceholderMarkerEmits(t *testing.T) {
	m := NewPlaceholderMarker()
	if !m.UsingPlaceholder() {
		t.Errorf("placeholder marker reports UsingPlaceholder=false")
	}
	mark := m.Sign([]byte("test"))
	if !strings.HasPrefix(mark, "lore@v1:") {
		t.Errorf("placeholder mark missing prefix: %q", mark)
	}
}

// TestPlaceholderMarkerVerifyRefuses pins that a placeholder marker
// refuses to Verify (regulator-side refusal of placeholder marks).
func TestPlaceholderMarkerVerifyRefuses(t *testing.T) {
	m := NewPlaceholderMarker()
	mark := m.Sign([]byte("test"))
	if err := m.Verify([]byte("test"), mark); err != ErrMarkerNotConfigured {
		t.Errorf("placeholder Verify = %v, want ErrMarkerNotConfigured", err)
	}
}

// TestKAT1ByteIdentityInternal verifies that the internal-package
// HMAC-SHA256 produces the cohort canonical KAT-1 hex (without taking
// a dependency on the lore package — pure inline re-derivation).
//
// R145.C FIREWALL-TEST-DISCIPLINE + R151 R-KAT-AS-COHORT-INVARIANT-PIN.
func TestKAT1ByteIdentityInternal(t *testing.T) {
	const wantHex = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

	mac := hmac.New(sha256.New, []byte{}) // empty key per cohort canonical
	mac.Write([]byte{0x01})
	mac.Write(make([]byte, 32))
	gotDigest := mac.Sum(nil)

	gotHex := encodeHex(gotDigest)
	if gotHex != wantHex {
		t.Errorf("KAT-1 HMAC-SHA256 hex = %q, want %q (cohort cross-substrate parity broken)", gotHex, wantHex)
	}
}

// encodeHex is a stdlib-only hex encoder (avoids the encoding/hex
// import to keep the test dependency surface minimal).
func encodeHex(b []byte) string {
	const hexchars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexchars[x>>4]
		out[i*2+1] = hexchars[x&0x0f]
	}
	return string(out)
}
