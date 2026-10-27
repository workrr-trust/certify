// Signed trust policy and revocation feed (spec §7).
//
// Kept apart from trustpolicy.go so a change to the embedded certifier list
// rebases as data in that file, not as a rewrite of signature and rollback checks.
package certify

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	signedBlobMediaType         = "application/vnd.workrr.signed-blob+json;version=1"
	trustPolicyPayload          = "application/vnd.workrr.trust-policy+json"
	revocationEntryPayload      = "application/vnd.workrr.revocation-entry+json"
	revocationCheckpointPayload = "application/vnd.workrr.revocation-checkpoint+json"
	trustPolicySchema           = "workrr-trust-policy-v1"
	revocationEntrySchema       = "workrr-revocation-v1"
	revocationCheckpointSchema  = "workrr-revocation-checkpoint-v1"
	genesisPrev                 = "0000000000000000000000000000000000000000000000000000000000000000"
	embeddedPolicySequence      = 0
	policyCacheTTLSeconds       = 60 * 60
	defaultTrustAPI             = "https://trust-api.workrr.ai"
	maxSignedBlobBytes          = 256 * 1024
	maxRevocationEntries        = 10000
	maxSequence                 = 9007199254740991 // 2^53-1, so TS and Go agree
	offlineWarning              = "offline: using the embedded trust policy; revocation was not checked"
	signatureInvalidWarning     = "trust policy signature invalid; using the embedded trust policy"
	fetchFailedEmbeddedWarning  = "trust policy fetch failed; using the embedded trust policy"
	fetchFailedCacheWarning     = "trust policy fetch failed; using cached trust policy"
	revocationUncheckedWarning  = "revocation was not checked"
)

// OfflineWarning is the note verify prints for --offline.
const OfflineWarning = offlineWarning

var (
	timestampRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	hex64Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sha256Re    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	gitSHARe    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	logIndexRe  = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	reasonRe    = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,200}$`)
	base64Re    = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
)

// TrustPolicySigner is the GitHub Actions identity allowed to sign a trust policy.
// BuildSignerDigests stays empty until the first tagged run; pin that commit once it exists.
var TrustPolicySigner = AcceptedSigner{
	Forge:                  ForgeGitHub,
	Issuer:                 "https://token.actions.githubusercontent.com",
	SubjectAlternativeName: `^https://github\.com/workrr-trust/certify/\.github/workflows/trust-policy\.yml@refs/tags/v\d+\.\d+\.\d+$`,
	BuildSignerDigests:     []string{},
}

// RevocationSigner is the GitHub Actions identity allowed to sign revocation entries.
var RevocationSigner = AcceptedSigner{
	Forge:                  ForgeGitHub,
	Issuer:                 "https://token.actions.githubusercontent.com",
	SubjectAlternativeName: `^https://github\.com/workrr-trust/certify/\.github/workflows/revoke\.yml@refs/tags/v\d+\.\d+\.\d+$`,
	BuildSignerDigests:     []string{},
}

// DefaultRevocationFeed is the revocation collection on the trust API.
func DefaultRevocationFeed() string { return defaultTrustAPI + "/v1/revocations" }

type signedBlob struct {
	MediaType   string `json:"mediaType"`
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signature   struct {
		Algorithm string          `json:"algorithm"`
		PublicKey string          `json:"publicKey"`
		Sig       string          `json:"sig"`
		Bundle    json.RawMessage `json:"bundle"`
	} `json:"signature"`
}

// TrustPolicyDocument is the signed policy body (spec §7).
type TrustPolicyDocument struct {
	Schema                string            `json:"schema"`
	Sequence              int               `json:"sequence"`
	IssuedAt              string            `json:"issuedAt"`
	Signers               []AcceptedSigner  `json:"signers"`
	BaselinePolicyDigests map[string]string `json:"baselinePolicyDigests"`
	RevocationFeed        string            `json:"revocationFeed"`
	RevocationWatermark   int               `json:"revocationWatermark"`
	RevocationHead        string            `json:"revocationHead"`
}

// RevocationEntry is one signed revocation (spec §7).
type RevocationEntry struct {
	Schema    string            `json:"schema"`
	Sequence  int               `json:"sequence"`
	Subject   RevocationSubject `json:"subject"`
	Reason    string            `json:"reason"`
	Timestamp string            `json:"timestamp"`
	Signer    string            `json:"signer"`
	Prev      string            `json:"prev"`
}

// RevocationSubject names an artifact digest or a certificate log index, never both.
type RevocationSubject struct {
	ArtifactDigest string `json:"artifactDigest,omitempty"`
	LogIndex       string `json:"logIndex,omitempty"`
}

// RevocationCheckpoint commits to the head of the revocation chain.
type RevocationCheckpoint struct {
	Schema    string `json:"schema"`
	Sequence  int    `json:"sequence"`
	Head      string `json:"head"`
	Timestamp string `json:"timestamp"`
	Signer    string `json:"signer"`
}

type policyDecision struct {
	OK       bool   `json:"ok"`
	Sequence int    `json:"sequence,omitempty"`
	Schema   string `json:"schema,omitempty"`
	Error    string `json:"error,omitempty"`
}

type revocationDecision struct {
	OK     bool   `json:"ok"`
	Status string `json:"status,omitempty"`
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
}

type offlineDecision struct {
	Source            string `json:"source"`
	RevocationChecked bool   `json:"revocationChecked"`
	Warning           string `json:"warning"`
}

func rollbackError(kind string, got, floor int) string {
	return fmt.Sprintf("ROLLBACK: %s sequence %d is older than %d", kind, got, floor)
}

func decodeStrictBase64(s string) ([]byte, error) {
	if len(s) == 0 || len(s)%4 != 0 || !base64Re.MatchString(s) {
		return nil, fmt.Errorf("malformed signed blob")
	}
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(buf) != s {
		return nil, fmt.Errorf("malformed signed blob")
	}
	return buf, nil
}

func keyAllowed(pub []byte, allowKeys []string) bool {
	ok := false
	for _, k := range allowKeys {
		raw, err := decodeStrictBase64(k)
		if err != nil || len(raw) != len(pub) {
			continue
		}
		if subtle.ConstantTimeCompare(raw, pub) == 1 {
			ok = true
		}
	}
	return ok
}

func openEd25519(blob *signedBlob, allowKeys []string) (string, error) {
	if blob.Signature.Algorithm != "ed25519" {
		return "", fmt.Errorf("malformed signed blob")
	}
	pub, err := decodeStrictBase64(blob.Signature.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("malformed signed blob")
	}
	sig, err := decodeStrictBase64(blob.Signature.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("malformed signed blob")
	}
	payload, err := decodeStrictBase64(blob.Payload)
	if err != nil {
		return "", err
	}
	if !keyAllowed(pub, allowKeys) {
		return "", fmt.Errorf("signer is not an accepted trust-policy identity")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return "", fmt.Errorf("signature invalid")
	}
	return canonicalPayloadText(payload)
}

func canonicalPayloadText(payload []byte) (string, error) {
	if len(payload) == 0 || len(payload) > maxSignedBlobBytes {
		return "", fmt.Errorf("malformed signed blob")
	}
	v, err := DecodeJSON(payload)
	if err != nil {
		return "", fmt.Errorf("malformed signed blob")
	}
	s, err := CanonicalJSON(v)
	if err != nil || s != string(payload) {
		return "", fmt.Errorf("not canonical JSON")
	}
	return s, nil
}

func parseBlob(raw json.RawMessage) (*signedBlob, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("malformed signed blob")
	}
	var blob signedBlob
	if err := json.Unmarshal(raw, &blob); err != nil {
		return nil, fmt.Errorf("malformed signed blob")
	}
	if blob.MediaType != signedBlobMediaType || blob.PayloadType == "" || blob.Payload == "" {
		return nil, fmt.Errorf("malformed signed blob")
	}
	if blob.Signature.Algorithm != "ed25519" && blob.Signature.Algorithm != "sigstore" {
		return nil, fmt.Errorf("malformed signed blob")
	}
	return &blob, nil
}

func jsonInt(v any, min int) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return 0, false
	}
	i, err := strconv.Atoi(s)
	if err != nil || i < min || i > maxSequence {
		return 0, false
	}
	return i, true
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func parseSignerTree(v any) (AcceptedSigner, bool) {
	m, ok := asMap(v)
	if !ok {
		return AcceptedSigner{}, false
	}
	forge, _ := m["forge"].(string)
	if forge != string(ForgeGitHub) && forge != string(ForgeGitLab) {
		return AcceptedSigner{}, false
	}
	issuer, _ := m["issuer"].(string)
	san, _ := m["subjectAlternativeName"].(string)
	if !strings.HasPrefix(issuer, "https://") || san == "" {
		return AcceptedSigner{}, false
	}
	rawDigests, ok := m["buildSignerDigests"].([]any)
	if !ok {
		return AcceptedSigner{}, false
	}
	digests := make([]string, 0, len(rawDigests))
	for _, d := range rawDigests {
		s, ok := d.(string)
		if !ok || !gitSHARe.MatchString(s) {
			return AcceptedSigner{}, false
		}
		digests = append(digests, s)
	}
	role := ""
	if r, present := m["role"]; present {
		rs, _ := r.(string)
		if rs != "publisher" && rs != RoleObserver {
			return AcceptedSigner{}, false
		}
		if rs == RoleObserver {
			role = RoleObserver
		}
	}
	return AcceptedSigner{Forge: Forge(forge), Issuer: issuer, SubjectAlternativeName: san, BuildSignerDigests: digests, Role: role}, true
}

func parseTrustPolicy(payload string) (*TrustPolicyDocument, error) {
	v, err := DecodeJSON([]byte(payload))
	if err != nil {
		return nil, fmt.Errorf("malformed trust policy")
	}
	m, ok := asMap(v)
	if !ok {
		return nil, fmt.Errorf("malformed trust policy")
	}
	schema, _ := m["schema"].(string)
	seq, seqOK := jsonInt(m["sequence"], 1)
	watermark, waterOK := jsonInt(m["revocationWatermark"], 0)
	issuedAt, _ := m["issuedAt"].(string)
	feed, _ := m["revocationFeed"].(string)
	head, _ := m["revocationHead"].(string)
	if schema != trustPolicySchema || !seqOK || !waterOK || !timestampRe.MatchString(issuedAt) {
		return nil, fmt.Errorf("malformed trust policy")
	}
	if !strings.HasPrefix(feed, "https://") || !hex64Re.MatchString(head) {
		return nil, fmt.Errorf("malformed trust policy")
	}
	if watermark == 0 && head != genesisPrev {
		return nil, fmt.Errorf("malformed trust policy")
	}
	rawSigners, ok := m["signers"].([]any)
	if !ok || len(rawSigners) == 0 {
		return nil, fmt.Errorf("malformed trust policy")
	}
	signers := make([]AcceptedSigner, 0, len(rawSigners))
	for _, s := range rawSigners {
		signer, ok := parseSignerTree(s)
		if !ok {
			return nil, fmt.Errorf("malformed trust policy")
		}
		signers = append(signers, signer)
	}
	rawDigests, ok := asMap(m["baselinePolicyDigests"])
	if !ok {
		return nil, fmt.Errorf("malformed trust policy")
	}
	digests := map[string]string{}
	for name, digest := range rawDigests {
		s, ok := digest.(string)
		if name == "" || !ok || !sha256Re.MatchString(s) {
			return nil, fmt.Errorf("malformed trust policy")
		}
		digests[name] = s
	}
	return &TrustPolicyDocument{
		Schema: schema, Sequence: seq, IssuedAt: issuedAt, Signers: signers,
		BaselinePolicyDigests: digests, RevocationFeed: feed,
		RevocationWatermark: watermark, RevocationHead: head,
	}, nil
}

func parseRevocationEntry(payload string) (*RevocationEntry, error) {
	v, err := DecodeJSON([]byte(payload))
	if err != nil {
		return nil, fmt.Errorf("malformed revocation entry")
	}
	m, ok := asMap(v)
	if !ok {
		return nil, fmt.Errorf("malformed revocation entry")
	}
	schema, _ := m["schema"].(string)
	seq, seqOK := jsonInt(m["sequence"], 1)
	reason, _ := m["reason"].(string)
	timestamp, _ := m["timestamp"].(string)
	signer, _ := m["signer"].(string)
	prev, _ := m["prev"].(string)
	if schema != revocationEntrySchema || !seqOK || !reasonRe.MatchString(reason) || !timestampRe.MatchString(timestamp) {
		return nil, fmt.Errorf("malformed revocation entry")
	}
	if !strings.HasPrefix(signer, "https://") || !hex64Re.MatchString(prev) {
		return nil, fmt.Errorf("malformed revocation entry")
	}
	subject, ok := asMap(m["subject"])
	if !ok || len(subject) != 1 {
		return nil, fmt.Errorf("malformed revocation entry")
	}
	entry := &RevocationEntry{Schema: schema, Sequence: seq, Reason: reason, Timestamp: timestamp, Signer: signer, Prev: prev}
	if d, exists := subject["artifactDigest"]; exists {
		s, ok := d.(string)
		if !ok || !hex64Re.MatchString(s) {
			return nil, fmt.Errorf("malformed revocation entry")
		}
		entry.Subject.ArtifactDigest = s
		return entry, nil
	}
	if d, exists := subject["logIndex"]; exists {
		s, ok := d.(string)
		if !ok || !logIndexRe.MatchString(s) {
			return nil, fmt.Errorf("malformed revocation entry")
		}
		entry.Subject.LogIndex = s
		return entry, nil
	}
	return nil, fmt.Errorf("malformed revocation entry")
}

func parseCheckpoint(payload string) (*RevocationCheckpoint, error) {
	v, err := DecodeJSON([]byte(payload))
	if err != nil {
		return nil, fmt.Errorf("malformed revocation checkpoint")
	}
	m, ok := asMap(v)
	if !ok {
		return nil, fmt.Errorf("malformed revocation checkpoint")
	}
	schema, _ := m["schema"].(string)
	seq, seqOK := jsonInt(m["sequence"], 0)
	head, _ := m["head"].(string)
	timestamp, _ := m["timestamp"].(string)
	signer, _ := m["signer"].(string)
	if schema != revocationCheckpointSchema || !seqOK || !hex64Re.MatchString(head) || !timestampRe.MatchString(timestamp) || !strings.HasPrefix(signer, "https://") {
		return nil, fmt.Errorf("malformed revocation checkpoint")
	}
	return &RevocationCheckpoint{Schema: schema, Sequence: seq, Head: head, Timestamp: timestamp, Signer: signer}, nil
}

func decidePolicyPayload(payload string, floor int) policyDecision {
	if floor < 0 {
		return policyDecision{Error: "malformed trust policy"}
	}
	doc, err := parseTrustPolicy(payload)
	if err != nil {
		return policyDecision{Error: err.Error()}
	}
	if doc.Sequence < floor {
		return policyDecision{Error: rollbackError("trust policy", doc.Sequence, floor)}
	}
	return policyDecision{OK: true, Sequence: doc.Sequence, Schema: doc.Schema}
}

// DecidePolicy verifies an ed25519 policy blob and rejects an older sequence.
func DecidePolicy(raw json.RawMessage, floor int, allowKeys []string) policyDecision {
	blob, err := parseBlob(raw)
	if err != nil || blob.PayloadType != trustPolicyPayload {
		return policyDecision{Error: "malformed signed blob"}
	}
	payload, err := openEd25519(blob, allowKeys)
	if err != nil {
		return policyDecision{Error: err.Error()}
	}
	return decidePolicyPayload(payload, floor)
}

type openEntry struct {
	entry  *RevocationEntry
	digest string
}

// BlobOpener verifies one signed blob and returns its canonical payload.
type BlobOpener func(raw json.RawMessage, payloadType string) (string, error)

func ed25519Opener(allowKeys []string) BlobOpener {
	return func(raw json.RawMessage, payloadType string) (string, error) {
		blob, err := parseBlob(raw)
		if err != nil || blob.PayloadType != payloadType {
			return "", fmt.Errorf("malformed signed blob")
		}
		return openEd25519(blob, allowKeys)
	}
}

type revocationFeedInput struct {
	entryBlobs               []json.RawMessage
	checkpointBlob           json.RawMessage
	watermark                int
	revocationHead           string
	artifactDigest           string
	logIndexes               []string
	allowKeys                []string
	cachedCheckpointSequence int
	open                     BlobOpener
}

func verifyRevocationFeed(in revocationFeedInput) ([]*RevocationEntry, error) {
	if !hex64Re.MatchString(in.revocationHead) {
		return nil, fmt.Errorf("malformed revocation entry")
	}
	if len(in.entryBlobs) > maxRevocationEntries {
		return nil, fmt.Errorf("malformed revocation entry")
	}
	open := in.open
	if open == nil {
		open = ed25519Opener(in.allowKeys)
	}
	opened := make([]openEntry, 0, len(in.entryBlobs))
	for _, raw := range in.entryBlobs {
		payload, err := open(raw, revocationEntryPayload)
		if err != nil {
			return nil, err
		}
		entry, err := parseRevocationEntry(payload)
		if err != nil {
			return nil, err
		}
		opened = append(opened, openEntry{entry: entry, digest: SHA256Hex([]byte(payload))})
	}
	sort.Slice(opened, func(i, j int) bool { return opened[i].entry.Sequence < opened[j].entry.Sequence })
	var checkpoint *RevocationCheckpoint
	if len(in.checkpointBlob) != 0 && string(in.checkpointBlob) != "null" {
		payload, err := open(in.checkpointBlob, revocationCheckpointPayload)
		if err != nil {
			return nil, err
		}
		checkpoint, err = parseCheckpoint(payload)
		if err != nil {
			return nil, err
		}
	}
	if checkpoint != nil && checkpoint.Sequence < in.cachedCheckpointSequence {
		return nil, fmt.Errorf("%s", rollbackError("revocation checkpoint", checkpoint.Sequence, in.cachedCheckpointSequence))
	}
	if err := checkChain(opened, checkpoint, in.watermark, in.revocationHead); err != nil {
		return nil, err
	}
	out := make([]*RevocationEntry, len(opened))
	for i := range opened {
		out[i] = opened[i].entry
	}
	return out, nil
}

func checkChain(entries []openEntry, checkpoint *RevocationCheckpoint, watermark int, head string) error {
	if len(entries) == 0 {
		if watermark == 0 && checkpoint == nil {
			return nil
		}
		if checkpoint == nil {
			return fmt.Errorf("revocation checkpoint missing")
		}
		if checkpoint.Sequence < watermark {
			return fmt.Errorf("revocation feed truncated")
		}
		if checkpoint.Sequence == watermark && checkpoint.Head == head {
			return nil
		}
		return fmt.Errorf("revocation chain invalid")
	}
	if checkpoint == nil {
		return fmt.Errorf("revocation checkpoint missing")
	}
	expectedSeq := watermark + 1
	expectedPrev := head
	for _, item := range entries {
		if item.entry.Sequence != expectedSeq || item.entry.Prev != expectedPrev {
			return fmt.Errorf("revocation chain invalid")
		}
		expectedPrev = item.digest
		expectedSeq++
	}
	last := entries[len(entries)-1]
	if last.entry.Sequence != checkpoint.Sequence || expectedPrev != checkpoint.Head {
		return fmt.Errorf("revocation chain invalid")
	}
	if checkpoint.Sequence < watermark {
		return fmt.Errorf("revocation feed truncated")
	}
	return nil
}

// DecideRevocation verifies the feed and reports REVOKED when an entry matches.
func DecideRevocation(in revocationFeedInput) revocationDecision {
	if !hex64Re.MatchString(in.artifactDigest) {
		return revocationDecision{Error: "malformed revocation entry"}
	}
	entries, err := verifyRevocationFeed(in)
	if err != nil {
		return revocationDecision{Error: err.Error()}
	}
	if hit := findRevocation(entries, in.artifactDigest, in.logIndexes); hit != nil {
		return revocationDecision{Status: "REVOKED", Reason: hit.Reason}
	}
	return revocationDecision{OK: true}
}

func findRevocation(entries []*RevocationEntry, artifactDigest string, logIndexes []string) *RevocationEntry {
	digest := strings.ToLower(artifactDigest)
	for _, e := range entries {
		if e.Subject.ArtifactDigest != "" && e.Subject.ArtifactDigest == digest {
			return e
		}
		if e.Subject.LogIndex != "" {
			for _, idx := range logIndexes {
				if idx == e.Subject.LogIndex {
					return e
				}
			}
		}
	}
	return nil
}

// RevocationError is "REVOKED: <reason>" when an entry matches, otherwise "".
func RevocationError(entries []*RevocationEntry, artifactDigest string, logIndexes []string) string {
	if hit := findRevocation(entries, artifactDigest, logIndexes); hit != nil {
		return "REVOKED: " + hit.Reason
	}
	return ""
}

// BaselineRejected reports a certificate policy digest outside a signed allow-list.
func BaselineRejected(policyDigest string, allowed map[string]string) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, digest := range allowed {
		if digest == policyDigest && policyDigest != "" {
			return false
		}
	}
	return true
}

// OfflineFallback is the shared offline-vector result.
func OfflineFallback() offlineDecision {
	return offlineDecision{Source: "embedded", RevocationChecked: false, Warning: offlineWarning}
}
