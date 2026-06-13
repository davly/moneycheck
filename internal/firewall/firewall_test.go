// Package firewall — R145.C FIREWALL-TEST-DISCIPLINE pins for moneycheck.
//
// 2026-05-27 new-flagship-inception ship. Pure-test package: zero
// production code. Tests in this file pin **inception observable
// invariants** as the gold standard. If any of these tests start
// failing, it means a future change has accidentally crossed a
// substrate-boundary that was out of scope for this scaffold.
//
// R145.C shape (per godfather session memory 2026-05-22): each pin
// states what was true at inception and MUST stay true thereafter.
// To change one of these invariants, an agent MUST open a sibling
// R145.B branch with paired regression tests — not silently flip a
// default in a feature-additive ship.
//
// moneycheck's classification at the time of inception:
//
//   - **Substrate-shaped UK financial-services regulatory-compliance
//     Go library.** Composes PSR 2017 + PSR (Amendment) 2024 + POCA §330
//     + FCA COBS 4 + PSD2 SCA RTS into a single Go library + CLI.
//
//   - **No daemon, no HTTP listener, no HTTP client, no DB, no auth,
//     no PII persistence, no env-var reads in library packages.** This
//     is the inception substrate shape that SECURITY.md declares.
//
//   - **R174 5-of-5 cohort maturity FROM INCEPTION.** Five dedicated
//     cohort packages (firewall/lore/mirrormark/manifest/honest) plus
//     three domain packages (psr_app_fraud/aml_sar/audit_ledger).
//
//   - **R175 production-wired Mirror-Mark FROM INCEPTION.** The
//     audit-ledger Emit() stamps every entry with a Mirror-Mark v1
//     HMAC over the canonical body (with mark cleared). Cold-verify
//     holds without trusting the PSP filesystem.
//
// R145.B AMENDMENT (2026-06-12, branch claude/stele-anchor-2026-06-12):
// moneycheck is wired as a flagship consumer of the Stele
// verified-trust spine. Two inception invariants are deliberately
// NARROWED (not dropped) on this sibling branch, with paired
// regression pins in TestR145B_SteleAnchorConfinement:
//
//   - HTTP CLIENT: permitted ONLY in internal/stele/ (a 5s-timeout
//     stdlib client POSTing run-ledger anchors to the spine's
//     /v1/verdicts). Listener primitives stay banned EVERYWHERE,
//     including internal/stele/. The Phase-3 NCA SAR-Online envelope
//     encoder still needs its OWN R145.B branch.
//   - ENV READS: cmd/moneycheck/main.go was already exempt from the
//     library env-read ban at inception; the R145.B pin tightens that
//     exemption to exactly ONE site — os.Getenv(stele.EnvURL).
//     Unset/empty means anchoring is disabled and behavior is
//     byte-identical to the argv-only inception CLI.
//
// The firewall is the difference between "we say moneycheck has no
// HTTP listener" (decorative claim) and "moneycheck CANNOT have an
// HTTP listener under R145-strict without a sibling branch breaking
// this test" (executable claim).
package firewall

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/davly/moneycheck/internal/honest"
	"github.com/davly/moneycheck/internal/lore"
	"github.com/davly/moneycheck/internal/manifest"
	"github.com/davly/moneycheck/internal/mirrormark"
	"github.com/davly/moneycheck/internal/stele"
)

// repoRoot walks up from the test working directory until it finds
// the go.mod (moneycheck repo root). Returns the absolute path.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	cur := wd
	for i := 0; i < 8; i++ {
		gomod := filepath.Join(cur, "go.mod")
		if _, err := os.Stat(gomod); err == nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	t.Fatalf("could not locate go.mod walking up from %q", wd)
	return ""
}

// scanGoFiles walks cmd/ and internal/ and returns all .go source
// files (test files excluded by default).
func scanGoFiles(t *testing.T, includeTests bool) []string {
	t.Helper()
	root := repoRoot(t)
	var out []string
	roots := []string{filepath.Join(root, "cmd"), filepath.Join(root, "internal")}
	for _, r := range roots {
		_ = filepath.Walk(r, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			if !includeTests && strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// Exclude the firewall package itself from its own scans.
			if strings.Contains(path, string(filepath.Separator)+"firewall"+string(filepath.Separator)) {
				return nil
			}
			out = append(out, path)
			return nil
		})
	}
	return out
}

// scanLibraryGoFiles returns all .go production source files under
// internal/ EXCLUDING cmd/. cmd/main.go is allowed to read env vars
// (CLI surface); the library packages are not.
func scanLibraryGoFiles(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	var out []string
	_ = filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(path, string(filepath.Separator)+"firewall"+string(filepath.Separator)) {
			return nil
		}
		out = append(out, path)
		return nil
	})
	return out
}

// fileContains reports whether the given file contains any of the
// forbidden substring patterns.
func fileContains(t *testing.T, path string, patterns ...string) (bool, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	src := string(data)
	for _, p := range patterns {
		if strings.Contains(src, p) {
			return true, p
		}
	}
	return false, ""
}

// ---- Substrate-boundary firewall pins ---------------------------------

// inSteleDir reports whether path lives under internal/stele/ — the
// ONE package permitted to hold an HTTP client after the R145.B
// stele-anchor amendment (2026-06-12).
func inSteleDir(path string) bool {
	sep := string(filepath.Separator)
	return strings.Contains(path, sep+"stele"+sep)
}

// TestFirewall_NoNetHTTPListener pins that no production source file
// imports net/http for listener use. moneycheck is a library + CLI,
// not a daemon. R145.B stele-anchor amendment: internal/stele/ may
// import net/http (client-only — see TestFirewall_NoHTTPClient) but
// the listener PRIMITIVES stay banned everywhere, including
// internal/stele/.
func TestFirewall_NoNetHTTPListener(t *testing.T) {
	for _, path := range scanGoFiles(t, false) {
		patterns := []string{
			`"net/http"`,
			`http.ListenAndServe`,
			`net.Listen(`,
		}
		if inSteleDir(path) {
			// The bare import is the spine client's; listener
			// primitives remain forbidden even here.
			patterns = []string{
				`http.ListenAndServe`,
				`net.Listen(`,
				`httptest.NewServer`, // test-double servers belong in _test.go only
			}
		}
		if hit, p := fileContains(t, path, patterns...); hit {
			t.Errorf("R145 firewall violation: %s contains %q — net/http listener is out of scope; open a sibling branch", path, p)
		}
	}
}

// TestFirewall_NoHTTPClient pins that no production source file imports
// net/http for client use — EXCEPT internal/stele/ (R145.B
// stele-anchor amendment 2026-06-12: the spine-anchoring client is
// confined to that one package; paired pins in
// TestR145B_SteleAnchorConfinement). The NCA SAR-Online v2 envelope
// encoder is Phase 3 (deferred) and will live on its own R145.B branch
// with its own outbound HTTP surface.
func TestFirewall_NoHTTPClient(t *testing.T) {
	for _, path := range scanGoFiles(t, false) {
		if inSteleDir(path) {
			continue
		}
		if hit, p := fileContains(t, path,
			`"net/http"`,
			`http.Client`,
			`http.Get(`,
			`http.Post(`,
		); hit {
			t.Errorf("R145 firewall violation: %s contains %q — HTTP client out of scope outside internal/stele", path, p)
		}
	}
}

// TestFirewall_NoDatabaseSQL pins that no production source file
// imports database/sql or any DB driver. The Go layer is stateless;
// host PSP integrations provide the persistent ledger.
func TestFirewall_NoDatabaseSQL(t *testing.T) {
	for _, path := range scanGoFiles(t, false) {
		if hit, p := fileContains(t, path,
			`"database/sql"`,
			`"github.com/mattn/go-sqlite3"`,
			`"github.com/jackc/pgx`,
			`"github.com/lib/pq"`,
			`sql.Open(`,
		); hit {
			t.Errorf("R145 firewall violation: %s contains %q — DB substrate is out of scope at inception", path, p)
		}
	}
}

// TestFirewall_NoLibraryEnvVarReads pins that no LIBRARY source file
// reads environment variables. cmd/main.go is allowed to read env
// vars for CLI configuration; the internal/* packages are not.
func TestFirewall_NoLibraryEnvVarReads(t *testing.T) {
	for _, path := range scanLibraryGoFiles(t) {
		if hit, p := fileContains(t, path,
			`os.Getenv(`,
			`os.LookupEnv(`,
			`os.Environ(`,
		); hit {
			t.Errorf("R145 firewall violation: %s contains %q — env-var reads are out of scope for library packages (cmd/ is exempt)", path, p)
		}
	}
}

// TestFirewall_NoAuthCrypto pins that no production source file imports
// auth/identity primitives (jwt / bcrypt / pbkdf2 / crypto/tls). Phase 1
// scaffold is offline; Phase 2+ host integrations provide auth.
func TestFirewall_NoAuthCrypto(t *testing.T) {
	for _, path := range scanGoFiles(t, false) {
		if hit, p := fileContains(t, path,
			`"github.com/golang-jwt/jwt`,
			`"golang.org/x/crypto/bcrypt"`,
			`"golang.org/x/crypto/pbkdf2"`,
			`"crypto/tls"`,
		); hit {
			t.Errorf("R145 firewall violation: %s contains %q — auth/identity primitives are out of scope", path, p)
		}
	}
}

// TestFirewall_NoExternalDeps pins that go.mod's require block is
// empty (zero external dependencies). moneycheck is pure Go 1.22
// stdlib from inception.
func TestFirewall_NoExternalDeps(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	src := string(data)
	if strings.Contains(src, "require ") {
		t.Errorf("R145 firewall violation: go.mod contains a 'require' block; moneycheck MUST stay stdlib-only at inception.\ngo.mod content:\n%s", src)
	}
	gosum := filepath.Join(root, "go.sum")
	if _, err := os.Stat(gosum); err == nil {
		t.Errorf("R145 firewall violation: go.sum exists at %q; stdlib-only repos should not have one", gosum)
	}
}

// ---- R145.B stele-anchor paired regression pins (2026-06-12) ----------

// TestR145B_SteleAnchorConfinement is the paired regression pin for
// the two NARROWED inception invariants (HTTP client + env read). It
// pins the NEW invariant shape so any further drift breaks a test:
//
//  1. every production net/http usage lives under internal/stele/;
//  2. the stele client carries the 5-second timeout;
//  3. os.Getenv appears in exactly one production file
//     (cmd/moneycheck/main.go) and only as os.Getenv(stele.EnvURL);
//     no os.LookupEnv / os.Environ anywhere;
//  4. the spine wire-contract constants hold (env var name,
//     substrate, honest oracle-strength label).
func TestR145B_SteleAnchorConfinement(t *testing.T) {
	var netHTTPFiles, getenvFiles []string
	for _, path := range scanGoFiles(t, false) {
		if hit, _ := fileContains(t, path, `"net/http"`); hit {
			netHTTPFiles = append(netHTTPFiles, path)
		}
		if hit, _ := fileContains(t, path, `os.Getenv(`); hit {
			getenvFiles = append(getenvFiles, path)
		}
		// os.LookupEnv / os.Environ stay banned EVERYWHERE — no
		// R145.B exemption was opened for them.
		if hit, p := fileContains(t, path, `os.LookupEnv(`, `os.Environ(`); hit {
			t.Errorf("R145.B pin violation: %s contains %q — only os.Getenv(stele.EnvURL) was exempted", path, p)
		}
	}

	// (1) net/http confined to internal/stele/ — and present there
	// (the wire is load-bearing, not decorative).
	if len(netHTTPFiles) == 0 {
		t.Errorf("R145.B pin violation: no production file imports net/http — the stele spine wire is gone; re-pin the firewall if this is deliberate")
	}
	for _, path := range netHTTPFiles {
		if !inSteleDir(path) {
			t.Errorf("R145.B pin violation: %s imports net/http outside internal/stele/", path)
		}
	}

	// (2) the stele client keeps its 5s timeout.
	steleSrc := filepath.Join(repoRoot(t), "internal", "stele", "stele.go")
	if hit, _ := fileContains(t, steleSrc, `Timeout: 5 * time.Second`); !hit {
		t.Errorf("R145.B pin violation: %s missing the 5-second http.Client timeout", steleSrc)
	}

	// (3) exactly one env-read site: os.Getenv(stele.EnvURL) in
	// cmd/moneycheck/main.go.
	wantGetenv := filepath.Join(repoRoot(t), "cmd", "moneycheck", "main.go")
	if len(getenvFiles) != 1 || getenvFiles[0] != wantGetenv {
		t.Errorf("R145.B pin violation: os.Getenv sites = %v, want exactly [%s]", getenvFiles, wantGetenv)
	}
	if hit, _ := fileContains(t, wantGetenv, `os.Getenv(stele.EnvURL)`); !hit {
		t.Errorf("R145.B pin violation: %s does not read os.Getenv(stele.EnvURL)", wantGetenv)
	}

	// (4) spine wire-contract constants.
	if stele.EnvURL != "MONEYCHECK_STELE_URL" {
		t.Errorf("R145.B pin violation: stele.EnvURL = %q, want MONEYCHECK_STELE_URL", stele.EnvURL)
	}
	if stele.Substrate != "flagships/moneycheck/audit-ledger" {
		t.Errorf("R145.B pin violation: stele.Substrate = %q, want flagships/moneycheck/audit-ledger", stele.Substrate)
	}
	if stele.OracleStrengthSelfCheck != "Self-Check" {
		t.Errorf("R145.B pin violation: stele.OracleStrengthSelfCheck = %q, want Self-Check (honesty label is load-bearing)", stele.OracleStrengthSelfCheck)
	}
}

// ---- R174 5-of-5 cohort-package on-disk presence pins -----------------

// TestFirewall_R174_FivePackagesPresent pins the R174 5-of-5 cohort
// maturity verdict: all five cohort packages MUST exist on disk.
func TestFirewall_R174_FivePackagesPresent(t *testing.T) {
	root := repoRoot(t)
	want := []string{
		"internal/firewall",
		"internal/lore",
		"internal/mirrormark",
		"internal/manifest",
		"internal/honest",
	}
	for _, sub := range want {
		path := filepath.Join(root, sub)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("R174 5-of-5 violation: %s does not exist (%v)", path, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("R174 5-of-5 violation: %s exists but is not a directory", path)
		}
	}
}

// TestFirewall_R174_DomainPackagesPresent pins the three domain
// packages (psr_app_fraud / aml_sar / audit_ledger) MUST exist on
// disk. They compose the regulatory disposition + filing + ledger
// surface.
func TestFirewall_R174_DomainPackagesPresent(t *testing.T) {
	root := repoRoot(t)
	want := []string{
		"internal/psr_app_fraud",
		"internal/aml_sar",
		"internal/audit_ledger",
	}
	for _, sub := range want {
		path := filepath.Join(root, sub)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("domain-package violation: %s does not exist (%v)", path, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("domain-package violation: %s exists but is not a directory", path)
		}
	}
}

// ---- R151 KAT-1 cohort cross-substrate parity pins --------------------

// TestFirewall_R151_KAT1HexLiteral pins the cohort-canonical KAT-1
// hex literal byte-identically. R145.C verify-not-inherit: this test
// re-derives the KAT-1 vector inline via raw stdlib hmac.New rather
// than calling lore.ComputeKAT1.
func TestFirewall_R151_KAT1HexLiteral(t *testing.T) {
	const wantHex = "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

	// Inline re-derivation (verify-not-inherit firewall).
	mac := hmac.New(sha256.New, []byte{})
	mac.Write([]byte{0x01})
	mac.Write(make([]byte, 32))
	gotHex := hex.EncodeToString(mac.Sum(nil))

	if gotHex != wantHex {
		t.Errorf("KAT-1 inline re-derivation = %q, want %q", gotHex, wantHex)
	}
	if lore.KAT1Digest != wantHex {
		t.Errorf("lore.KAT1Digest = %q, want %q (cohort canonical hex literal pin)", lore.KAT1Digest, wantHex)
	}
	if got := lore.ComputeKAT1(); got != wantHex {
		t.Errorf("lore.ComputeKAT1() = %q, want %q", got, wantHex)
	}
}

// ---- L43 Mirror-Mark v1 cohort wire-form pins ------------------------

// TestFirewall_L43_MirrorMarkPrefix pins the cohort-canonical
// "lore@v1:" prefix. Drift breaks downstream identification of v1
// marks.
func TestFirewall_L43_MirrorMarkPrefix(t *testing.T) {
	if mirrormark.MarkPrefix != "lore@v1:" {
		t.Errorf("mirrormark.MarkPrefix = %q, want \"lore@v1:\" (cohort canonical L43 wire-form)", mirrormark.MarkPrefix)
	}
}

// TestFirewall_L43_MirrorMarkBodyShape pins the canonical body shape
// constants (8-byte corpus prefix + 32-byte HMAC = 40-byte body).
func TestFirewall_L43_MirrorMarkBodyShape(t *testing.T) {
	if mirrormark.MarkCorpusPrefixLen != 8 {
		t.Errorf("mirrormark.MarkCorpusPrefixLen = %d, want 8", mirrormark.MarkCorpusPrefixLen)
	}
	if mirrormark.MarkBodyLen != 40 {
		t.Errorf("mirrormark.MarkBodyLen = %d, want 40", mirrormark.MarkBodyLen)
	}
}

// ---- R150 PARALLEL-MAP review-metadata pins --------------------------

// TestFirewall_R150_SchemaVersionV1 pins the cohort-canonical R150
// schema version.
func TestFirewall_R150_SchemaVersionV1(t *testing.T) {
	if manifest.SchemaVersion != 1 {
		t.Errorf("manifest.SchemaVersion = %d, want 1 (cohort canonical R150)", manifest.SchemaVersion)
	}
}

// TestFirewall_R150_SeedShape pins the inception 13-entry inventory
// (5 RegRegime + 3 SARFilingChannel + 4 SCAExemption + 1 CounselReview).
func TestFirewall_R150_SeedShape(t *testing.T) {
	m := manifest.Seed()
	if len(m) != 13 {
		t.Errorf("manifest.Seed() length = %d, want 13 at inception", len(m))
	}
}

// TestFirewall_R150_R166_NoEntryReviewedByCounsel pins the Phase 1
// scaffold posture: NO entry carries ReviewedByCounsel=true. R166
// LIABILITY-FOOTER-CONST sibling.
func TestFirewall_R150_R166_NoEntryReviewedByCounsel(t *testing.T) {
	m := manifest.Seed()
	if got := m.CounselReviewedCount(); got != 0 {
		t.Errorf("Phase 1 CounselReviewedCount = %d, want 0 (R166 sibling)", got)
	}
}

// ---- R143 LOUD-ONCE + R143.A severity ladder pins --------------------

// TestFirewall_R143_LoudOncePrefix pins the cohort-canonical
// "[LOUD-ONCE-WARNING]" prefix.
func TestFirewall_R143_LoudOncePrefix(t *testing.T) {
	if honest.LoudOncePrefix != "[LOUD-ONCE-WARNING]" {
		t.Errorf("honest.LoudOncePrefix = %q, want \"[LOUD-ONCE-WARNING]\"", honest.LoudOncePrefix)
	}
}

// TestFirewall_R143_R143A_CanonicalAdvisoriesShape pins the brief-
// specified canonical advisories shape: 5 advisories + 3 Error + 2 Warn
// + 0 Info.
func TestFirewall_R143_R143A_CanonicalAdvisoriesShape(t *testing.T) {
	advs := honest.CanonicalAdvisories()
	if len(advs) != 5 {
		t.Errorf("CanonicalAdvisories() length = %d, want 5 (brief shape)", len(advs))
	}
	counts := map[honest.Severity]int{}
	for _, a := range advs {
		counts[a.Severity]++
	}
	if counts[honest.SeverityError] != 3 {
		t.Errorf("Error count = %d, want 3", counts[honest.SeverityError])
	}
	if counts[honest.SeverityWarn] != 2 {
		t.Errorf("Warn count = %d, want 2", counts[honest.SeverityWarn])
	}
}

// TestFirewall_R143_CodeConstants pins the canonical advisory code
// constants match the brief literally.
func TestFirewall_R143_CodeConstants(t *testing.T) {
	pairs := map[string]string{
		honest.CodePSRAppFraudReimbursementNotReviewed: "MONEYCHECK_PSR_APP_FRAUD_REIMBURSEMENT_NOT_REVIEWED",
		honest.CodeAMLSARFilingPlaceholder:             "MONEYCHECK_AML_SAR_FILING_PLACEHOLDER",
		honest.CodeFCACRD4DisclosureRequired:           "MONEYCHECK_FCA_CRD_4_DISCLOSURE_REQUIRED",
		honest.CodePSD2SCAEscapeInvariant:              "MONEYCHECK_PSD2_SCA_ESCAPE_INVARIANT",
		honest.CodeReviewedByCounselFalse:              "MONEYCHECK_REVIEWED_BY_COUNSEL_FALSE",
	}
	for got, want := range pairs {
		if got != want {
			t.Errorf("advisory code constant = %q, want %q", got, want)
		}
	}
}

// ---- R175 production-wired audit-ledger Mirror-Mark pin --------------

// TestFirewall_R175_AuditLedgerMarkerSignCall pins the brief-specified
// R175 criterion 1: the audit-ledger Emit() must call marker.Sign() in
// production code (non-test). Grep verification.
func TestFirewall_R175_AuditLedgerMarkerSignCall(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "internal", "audit_ledger", "ledger.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("R175 firewall: cannot read %q: %v", path, err)
	}
	src := string(data)
	if !strings.Contains(src, ".Sign(") {
		t.Errorf("R175 firewall violation: %s does not contain a .Sign() call — R175 criterion 1 (production-traffic emit-path) broken", path)
	}
}
