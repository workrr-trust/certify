// Fetch, verify, and cache the signed trust policy.
//
// This is the verifier's policy-loading path. It does not edit the embedded
// signer list in trustpolicy.go; it reads DefaultTrustPolicy and, once a signed
// document verifies, uses that document's signers instead.
package certify

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

const localFileWarning = "local trust policy file; signature was not checked"

// LoadedPolicy is the trust policy a verify command should use.
type LoadedPolicy struct {
	Policy                TrustPolicy
	Source                string
	Warnings              []string
	Revocations           []*RevocationEntry
	RevocationChecked     bool
	BaselinePolicyDigests map[string]string
	Status                string // ok, rollback, rejected
	Error                 string
	Document              *TrustPolicyDocument
}

// LoadOptions configures policy loading. Zero values match the CLI defaults.
type LoadOptions struct {
	Offline          bool
	File             string
	CachePath        string
	Now              time.Time
	BaseURL          string
	HTTPClient       *http.Client
	AllowEd25519Keys []string
	FloorSequence    int
	TrustedRoot      string
	floorSet         bool
}

type cacheRecord struct {
	FetchedAt          int64
	CheckpointSequence int
	Document           *TrustPolicyDocument
	Blob               json.RawMessage
}

func defaultCachePath() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "workrr", "trust-policy.json"), nil
}

func embeddedDocument() *TrustPolicyDocument {
	return &TrustPolicyDocument{
		Schema:                trustPolicySchema,
		Sequence:              embeddedPolicySequence,
		IssuedAt:              "1970-01-01T00:00:00Z",
		Signers:               DefaultTrustPolicy.Signers,
		BaselinePolicyDigests: map[string]string{baselineName(): BaselinePolicy().Digest()},
		RevocationFeed:        DefaultRevocationFeed(),
		RevocationWatermark:   0,
		RevocationHead:        genesisPrev,
	}
}

func baselineName() string {
	p := BaselinePolicy()
	if p.Name != nil {
		return *p.Name
	}
	return "workrr-baseline-v0.1"
}

func embeddedLoaded(warnings []string) *LoadedPolicy {
	return &LoadedPolicy{
		Policy: DefaultTrustPolicy, Source: "embedded", Warnings: warnings,
		Revocations: []*RevocationEntry{}, Status: "ok",
	}
}

func fromDocument(doc *TrustPolicyDocument, source string, warnings []string) *LoadedPolicy {
	return &LoadedPolicy{
		Policy:                TrustPolicy{Version: doc.Schema, Signers: doc.Signers},
		Source:                source,
		Warnings:              warnings,
		Revocations:           []*RevocationEntry{},
		BaselinePolicyDigests: doc.BaselinePolicyDigests,
		Status:                "ok",
		Document:              doc,
	}
}

func (o LoadOptions) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

func (o LoadOptions) floor() int {
	if o.floorSet {
		return o.FloorSequence
	}
	return embeddedPolicySequence
}

func (o LoadOptions) client() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (o LoadOptions) base() string {
	base := o.BaseURL
	if base == "" {
		base = os.Getenv("WORKRR_TRUST_API")
	}
	if base == "" {
		base = defaultTrustAPI
	}
	return strings.TrimRight(base, "/")
}

func openBlob(blob *signedBlob, opts LoadOptions) (string, error) {
	if blob.Signature.Algorithm == "ed25519" {
		return openEd25519(blob, opts.AllowEd25519Keys)
	}
	if blob.Signature.Algorithm != "sigstore" || len(blob.Signature.Bundle) == 0 {
		return "", fmt.Errorf("malformed signed blob")
	}
	payload, err := decodeStrictBase64(blob.Payload)
	if err != nil {
		return "", err
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(blob.Signature.Bundle); err != nil {
		return "", fmt.Errorf("signature invalid")
	}
	tms := &TrustedMaterialSource{Path: opts.TrustedRoot}
	tm, err := tms.Get()
	if err != nil {
		return "", fmt.Errorf("signature invalid")
	}
	sum := sha256.Sum256(payload)
	signer, err := VerifySigstore(&b, tm, "sha256", sum[:])
	if err != nil {
		return "", fmt.Errorf("signature invalid")
	}
	expected := TrustPolicySigner
	if blob.PayloadType != trustPolicyPayload {
		expected = RevocationSigner
	}
	if MatchSigner(&TrustPolicy{Signers: []AcceptedSigner{expected}}, signer) == nil {
		return "", fmt.Errorf("signer is not an accepted trust-policy identity")
	}
	text, err := canonicalPayloadText(payload)
	if err != nil {
		return "", err
	}
	if blob.PayloadType == revocationEntryPayload || blob.PayloadType == revocationCheckpointPayload {
		var body struct {
			Signer string `json:"signer"`
		}
		if err := json.Unmarshal([]byte(text), &body); err != nil || body.Signer != signer.SAN {
			return "", fmt.Errorf("signer is not an accepted trust-policy identity")
		}
	}
	return text, nil
}

func readCache(path string, opts LoadOptions) *cacheRecord {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var parsed struct {
		FetchedAt          int64           `json:"fetchedAt"`
		CheckpointSequence int             `json:"checkpointSequence"`
		Blob               json.RawMessage `json:"blob"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.FetchedAt == 0 {
		return nil
	}
	blob, err := parseBlob(parsed.Blob)
	if err != nil {
		return nil
	}
	payload, err := openBlob(blob, opts)
	if err != nil {
		return nil
	}
	doc, err := parseTrustPolicy(payload)
	if err != nil {
		return nil
	}
	return &cacheRecord{FetchedAt: parsed.FetchedAt, CheckpointSequence: parsed.CheckpointSequence, Document: doc, Blob: parsed.Blob}
}

func writeCache(path string, rec *cacheRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{
		"fetchedAt": rec.FetchedAt, "checkpointSequence": rec.CheckpointSequence, "blob": json.RawMessage(rec.Blob),
	})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func fetchBytes(client *http.Client, url string) ([]byte, bool) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "workrr-trust/"+Version)
	res, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		io.Copy(io.Discard, res.Body)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, false
	}
	return body, true
}

func rejected(err string) *LoadedPolicy {
	status := "rejected"
	if strings.HasPrefix(err, "ROLLBACK:") {
		status = "rollback"
	}
	out := embeddedLoaded([]string{err})
	out.Status = status
	out.Error = err
	return out
}

func loadFile(opts LoadOptions) (*LoadedPolicy, error) {
	raw, err := os.ReadFile(opts.File)
	if err != nil {
		return nil, err
	}
	blob, blobErr := parseBlob(raw)
	if blobErr == nil {
		payload, err := openBlob(blob, opts)
		if err != nil {
			return rejected(err.Error()), nil
		}
		decision := decidePolicyPayload(payload, opts.floor())
		if !decision.OK {
			return rejected(decision.Error), nil
		}
		doc, err := parseTrustPolicy(payload)
		if err != nil {
			return rejected(err.Error()), nil
		}
		loaded := fromDocument(doc, "file", nil)
		if opts.Offline {
			loaded.Warnings = append(loaded.Warnings, offlineWarning)
			return loaded, nil
		}
		return attachRevocations(loaded, opts, 0), nil
	}
	var legacy TrustPolicy
	if err := json.Unmarshal(raw, &legacy); err != nil || legacy.Version == "" || legacy.Signers == nil {
		return rejected("malformed trust policy"), nil
	}
	loaded := &LoadedPolicy{
		Policy: legacy, Source: "file", Warnings: []string{localFileWarning},
		Revocations: []*RevocationEntry{}, Status: "ok",
	}
	if opts.Offline {
		loaded.Warnings = append(loaded.Warnings, offlineWarning)
		return loaded, nil
	}
	return attachRevocations(loaded, opts, 0), nil
}

// LoadTrustPolicy fetches the signed policy, or falls back as spec §7 describes.
func LoadTrustPolicy(opts LoadOptions) (*LoadedPolicy, error) {
	if opts.File != "" {
		return loadFile(opts)
	}
	if opts.Offline {
		return embeddedLoaded([]string{offlineWarning}), nil
	}
	cachePath := opts.CachePath
	if cachePath == "" {
		if p, err := defaultCachePath(); err == nil {
			cachePath = p
		}
	}
	cache := readCache(cachePath, opts)
	floor := opts.floor()
	if cache != nil && cache.Document.Sequence > floor {
		floor = cache.Document.Sequence
	}
	now := opts.now().UnixMilli()
	var loaded *LoadedPolicy
	checkpointSequence := 0
	if cache != nil {
		checkpointSequence = cache.CheckpointSequence
	}
	if cache != nil && now-cache.FetchedAt < policyCacheTTLSeconds*1000 && cache.Document.Sequence >= opts.floor() {
		loaded = fromDocument(cache.Document, "cache", nil)
	} else if body, ok := fetchBytes(opts.client(), opts.base()+"/v1/policy"); ok {
		if blob, err := parseBlob(body); err != nil {
			loaded = embeddedLoaded([]string{signatureInvalidWarning})
		} else if payload, err := openBlob(blob, opts); err != nil {
			loaded = embeddedLoaded([]string{signatureWarning(err.Error())})
		} else if decision := decidePolicyPayload(payload, floor); !decision.OK {
			return rejected(decision.Error), nil
		} else if doc, err := parseTrustPolicy(payload); err != nil {
			return rejected(err.Error()), nil
		} else {
			loaded = fromDocument(doc, "signed", nil)
			raw := json.RawMessage(body)
			if cachePath != "" {
				_ = writeCache(cachePath, &cacheRecord{FetchedAt: now, CheckpointSequence: checkpointSequence, Document: doc, Blob: raw})
			}
			if cache == nil {
				cache = &cacheRecord{Blob: raw, FetchedAt: now, Document: doc}
			} else {
				cache.Blob = raw
				cache.FetchedAt = now
				cache.Document = doc
			}
		}
	} else if cache != nil {
		loaded = fromDocument(cache.Document, "cache", []string{fetchFailedCacheWarning})
	} else {
		loaded = embeddedLoaded([]string{fetchFailedEmbeddedWarning})
	}
	if loaded.Status != "ok" {
		return loaded, nil
	}
	withFeed := attachRevocations(loaded, opts, checkpointSequence)
	if withFeed.Status == "ok" && withFeed.RevocationChecked && cachePath != "" && withFeed.Document != nil && cache != nil {
		highest := checkpointSequence
		for _, e := range withFeed.Revocations {
			if e.Sequence > highest {
				highest = e.Sequence
			}
		}
		if highest != checkpointSequence {
			_ = writeCache(cachePath, &cacheRecord{FetchedAt: cache.FetchedAt, CheckpointSequence: highest, Document: withFeed.Document, Blob: cache.Blob})
		}
	}
	return withFeed, nil
}

func signatureWarning(err string) string {
	if err == "signature invalid" || err == "signer is not an accepted trust-policy identity" {
		return signatureInvalidWarning
	}
	return err
}

func attachRevocations(loaded *LoadedPolicy, opts LoadOptions, cachedCheckpoint int) *LoadedPolicy {
	doc := loaded.Document
	if doc == nil {
		doc = embeddedDocument()
	}
	feed := strings.TrimRight(doc.RevocationFeed, "/")
	if loaded.Document == nil {
		feed = strings.TrimRight(DefaultRevocationFeed(), "/")
	}
	rawBody, ok := fetchBytes(opts.client(), fmt.Sprintf("%s/since/%d", feed, doc.RevocationWatermark))
	if !ok {
		loaded.Warnings = append(loaded.Warnings, revocationUncheckedWarning)
		return loaded
	}
	var body any
	dec := json.NewDecoder(bytes.NewReader(rawBody))
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil {
		return rejectedFeed(loaded, "malformed revocation feed")
	}
	m, ok := body.(map[string]any)
	if !ok {
		return rejectedFeed(loaded, "malformed revocation feed")
	}
	rawEntries, ok := m["entries"].([]any)
	if !ok {
		return rejectedFeed(loaded, "malformed revocation feed")
	}
	entries := make([]json.RawMessage, len(rawEntries))
	for i, e := range rawEntries {
		b, err := json.Marshal(e)
		if err != nil {
			return rejectedFeed(loaded, "malformed revocation feed")
		}
		entries[i] = b
	}
	var checkpoint json.RawMessage
	if c, exists := m["checkpoint"]; exists && c != nil {
		b, err := json.Marshal(c)
		if err != nil {
			return rejectedFeed(loaded, "malformed revocation feed")
		}
		checkpoint = b
	}
	verified, err := verifyRevocationFeed(revocationFeedInput{
		entryBlobs: entries, checkpointBlob: checkpoint,
		watermark: doc.RevocationWatermark, revocationHead: doc.RevocationHead,
		allowKeys: opts.AllowEd25519Keys, cachedCheckpointSequence: cachedCheckpoint,
		open: func(raw json.RawMessage, payloadType string) (string, error) {
			blob, err := parseBlob(raw)
			if err != nil || blob.PayloadType != payloadType {
				return "", fmt.Errorf("malformed signed blob")
			}
			return openBlob(blob, opts)
		},
	})
	if err != nil {
		return rejectedFeed(loaded, err.Error())
	}
	loaded.Revocations = verified
	loaded.RevocationChecked = true
	return loaded
}

func rejectedFeed(loaded *LoadedPolicy, err string) *LoadedPolicy {
	status := "rejected"
	if strings.HasPrefix(err, "ROLLBACK:") {
		status = "rollback"
	}
	loaded.Status = status
	loaded.Error = err
	loaded.Warnings = append(loaded.Warnings, err)
	loaded.Revocations = []*RevocationEntry{}
	loaded.RevocationChecked = false
	return loaded
}
