package certify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTrustFeedVectors(t *testing.T) {
	var file struct {
		PublicKey string `json:"publicKey"`
		Cases     []struct {
			ID             string            `json:"id"`
			Op             string            `json:"op"`
			FloorSequence  int               `json:"floorSequence"`
			Blob           json.RawMessage   `json:"blob"`
			ArtifactDigest string            `json:"artifactDigest"`
			LogIndexes     []string          `json:"logIndexes"`
			Watermark      int               `json:"watermark"`
			RevocationHead string            `json:"revocationHead"`
			Entries        []json.RawMessage `json:"entries"`
			Checkpoint     json.RawMessage   `json:"checkpoint"`
			Expect         json.RawMessage   `json:"expect"`
		} `json:"cases"`
	}
	readJSONFile(t, filepath.Join("..", "spec", "trust-feed", "vectors.json"), &file)
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			var got any
			switch c.Op {
			case "policy":
				got = DecidePolicy(c.Blob, c.FloorSequence, []string{file.PublicKey})
			case "revocation":
				got = DecideRevocation(revocationFeedInput{
					entryBlobs: c.Entries, checkpointBlob: c.Checkpoint,
					watermark: c.Watermark, revocationHead: c.RevocationHead,
					artifactDigest: c.ArtifactDigest, logIndexes: c.LogIndexes,
					allowKeys: []string{file.PublicKey},
				})
			case "offline":
				got = OfflineFallback()
			default:
				t.Fatalf("unknown op %s", c.Op)
			}
			if !jsonEqual(t, got, c.Expect) {
				b, _ := json.Marshal(got)
				t.Fatalf("got %s\nwant %s", b, c.Expect)
			}
		})
	}
}

func jsonEqual(t *testing.T, got any, want json.RawMessage) bool {
	t.Helper()
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var g, w any
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(g, w)
}

func TestTrustFeedSignersAreReleaseTags(t *testing.T) {
	policy := &TrustPolicy{Signers: []AcceptedSigner{TrustPolicySigner}}
	revocation := &TrustPolicy{Signers: []AcceptedSigner{RevocationSigner}}
	if MatchSigner(policy, &Signer{SAN: "https://github.com/workrr-trust/certify/.github/workflows/trust-policy.yml@refs/tags/v1.2.3", Issuer: TrustPolicySigner.Issuer}) == nil {
		t.Fatal("release tag should be accepted")
	}
	if MatchSigner(policy, &Signer{SAN: "https://github.com/workrr-trust/certify/.github/workflows/trust-policy.yml@refs/heads/main", Issuer: TrustPolicySigner.Issuer}) != nil {
		t.Fatal("refs/heads/main must not sign a trust policy")
	}
	if MatchSigner(policy, &Signer{SAN: "https://github.com/workrr-trust/certify/.github/workflows/certify.yml@refs/tags/v1.2.3", Issuer: TrustPolicySigner.Issuer}) != nil {
		t.Fatal("the certifier workflow must not sign a trust policy")
	}
	if MatchSigner(revocation, &Signer{SAN: "https://github.com/workrr-trust/certify/.github/workflows/revoke.yml@refs/tags/v1.2.3", Issuer: RevocationSigner.Issuer}) == nil {
		t.Fatal("revoke workflow tag should be accepted")
	}
	if MatchSigner(revocation, &Signer{SAN: "https://github.com/workrr-trust/certify/.github/workflows/revoke.yml@refs/heads/main", Issuer: RevocationSigner.Issuer}) != nil {
		t.Fatal("refs/heads/main must not sign a revocation")
	}
}

func TestLoadTrustPolicyOfflineAndFallback(t *testing.T) {
	var file struct {
		PublicKey string `json:"publicKey"`
		Cases     []struct {
			ID   string          `json:"id"`
			Blob json.RawMessage `json:"blob"`
		} `json:"cases"`
	}
	readJSONFile(t, filepath.Join("..", "spec", "trust-feed", "vectors.json"), &file)
	var valid, tampered json.RawMessage
	for _, c := range file.Cases {
		if c.ID == "valid-policy" {
			valid = c.Blob
		}
		if c.ID == "tampered-policy" {
			tampered = c.Blob
		}
	}
	dir := t.TempDir()
	now := time.UnixMilli(1_700_000_000_000)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/policy":
			w.Write(valid)
		case "/v1/revocations/since/0":
			w.Write([]byte(`{"since":0,"checkpoint":null,"entries":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := &http.Client{Transport: rewriteHost(srv.URL), Timeout: 5 * time.Second}
	keys := []string{file.PublicKey}

	offlineCalls := 0
	offlineClient := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		offlineCalls++
		return nil, os.ErrClosed
	})}
	offline, err := LoadTrustPolicy(LoadOptions{Offline: true, CachePath: filepath.Join(dir, "absent.json"), HTTPClient: offlineClient, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if offlineCalls != 0 || offline.Source != "embedded" || offline.RevocationChecked || len(offline.Warnings) != 1 || offline.Warnings[0] != offlineWarning {
		t.Fatalf("offline: calls=%d loaded=%+v", offlineCalls, offline)
	}

	cachePath := filepath.Join(dir, "trust-policy.json")
	loaded, err := LoadTrustPolicy(LoadOptions{
		CachePath: cachePath, AllowEd25519Keys: keys, HTTPClient: client, BaseURL: srv.URL, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Source != "signed" || loaded.Status != "ok" || !loaded.RevocationChecked || len(loaded.Warnings) != 0 || len(loaded.Revocations) != 0 {
		t.Fatalf("signed load: %+v", loaded)
	}

	cached, err := LoadTrustPolicy(LoadOptions{
		CachePath: cachePath, AllowEd25519Keys: keys, HTTPClient: client, BaseURL: srv.URL, Now: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cached.Source != "cache" {
		t.Fatalf("fresh cache source %s", cached.Source)
	}

	down := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/v1/policy") {
			return nil, os.ErrClosed
		}
		return rewriteHost(srv.URL).RoundTrip(r)
	})}
	stale, err := LoadTrustPolicy(LoadOptions{
		CachePath: cachePath, AllowEd25519Keys: keys, HTTPClient: down, BaseURL: srv.URL,
		Now: now.Add(policyCacheTTLSeconds*time.Second + time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if stale.Source != "cache" || !contains(stale.Warnings, fetchFailedCacheWarning) {
		t.Fatalf("stale cache: %+v", stale)
	}

	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/policy":
			w.Write(tampered)
		case "/v1/revocations/since/0":
			w.Write([]byte(`{"since":0,"checkpoint":null,"entries":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer badSrv.Close()
	fell, err := LoadTrustPolicy(LoadOptions{
		CachePath: filepath.Join(dir, "other.json"), AllowEd25519Keys: keys,
		HTTPClient: &http.Client{Transport: rewriteHost(badSrv.URL)}, BaseURL: badSrv.URL, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fell.Source != "embedded" || !contains(fell.Warnings, signatureInvalidWarning) || !fell.RevocationChecked {
		t.Fatalf("tampered fallback: %+v", fell)
	}

	missing, err := LoadTrustPolicy(LoadOptions{
		CachePath: filepath.Join(dir, "none.json"), AllowEd25519Keys: keys, Now: now,
		HTTPClient: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) { return nil, os.ErrClosed })},
		BaseURL:    "https://trust.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if missing.Source != "embedded" || missing.RevocationChecked || !contains(missing.Warnings, fetchFailedEmbeddedWarning) || !contains(missing.Warnings, revocationUncheckedWarning) {
		t.Fatalf("fetch failed: %+v", missing)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func rewriteHost(base string) http.RoundTripper {
	return roundTrip(func(r *http.Request) (*http.Response, error) {
		req := r.Clone(r.Context())
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://")
		return http.DefaultTransport.RoundTrip(req)
	})
}
