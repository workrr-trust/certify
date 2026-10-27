// Provenance: the artifact is committed, unchanged, at a known source commit.
package certify

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type Source struct {
	URI    string `json:"uri"`
	Commit string `json:"commit"`
	Path   string `json:"path"`
}

type ProvenanceResult struct {
	Result              string `json:"result"`
	UnchangedFromCommit bool   `json:"unchangedFromCommit"`
	Reason              string `json:"reason,omitempty"`
}

func git(cwd string, args ...string) (string, error) {
	out, err := exec.Command("git", append([]string{"-C", cwd}, args...)...).Output()
	return JSTrim(string(out)), err
}

var (
	sshRemoteRe  = regexp.MustCompile(`^git@([^:]+):(.+?)(\.git)?$`)
	dotGitRe     = regexp.MustCompile(`\.git$`)
	httpsCredsRe = regexp.MustCompile(`^https://[^@/]+@`)
)

// NormalizeRepoURI maps git@github.com:org/repo.git and
// https://github.com/org/repo.git to https://github.com/org/repo.
func NormalizeRepoURI(remote string) string {
	if m := sshRemoteRe.FindStringSubmatch(remote); m != nil {
		return "https://" + m[1] + "/" + m[2]
	}
	return httpsCredsRe.ReplaceAllLiteralString(dotGitRe.ReplaceAllLiteralString(remote, ""), "https://")
}

// CheckProvenance reads the source repo from CI or the origin remote. For a public
// scan, observedURI names the scanned repository instead (docs/public-scans.md).
func CheckProvenance(artifactPath string, observedURI ...string) (Source, ProvenanceResult, error) {
	abs, err := filepath.Abs(artifactPath)
	if err != nil {
		return Source{}, ProvenanceResult{}, err
	}
	if abs, err = filepath.EvalSymlinks(abs); err != nil {
		return Source{}, ProvenanceResult{}, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return Source{}, ProvenanceResult{}, err
	}
	dir := abs
	if !st.IsDir() {
		dir = filepath.Dir(abs)
	}
	top, err := git(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return Source{URI: "", Commit: strings.Repeat("0", 40), Path: artifactPath},
			ProvenanceResult{Result: "fail", UnchangedFromCommit: false, Reason: "not inside a git repository"}, nil
	}
	repoRoot, err := filepath.EvalSymlinks(top)
	if err != nil {
		return Source{}, ProvenanceResult{}, err
	}
	path, err := filepath.Rel(repoRoot, abs)
	if err != nil {
		return Source{}, ProvenanceResult{}, err
	}
	path = filepath.ToSlash(path)
	commit, err := git(repoRoot, "rev-parse", "HEAD")
	if err != nil {
		return Source{}, ProvenanceResult{}, err
	}

	// CI knows the canonical repo URL; locally fall back to the origin remote.
	uri := ""
	switch {
	case len(observedURI) > 0 && observedURI[0] != "":
		uri = NormalizeRepoURI(observedURI[0])
	case os.Getenv("GITHUB_SERVER_URL") != "" && os.Getenv("GITHUB_REPOSITORY") != "":
		uri = os.Getenv("GITHUB_SERVER_URL") + "/" + os.Getenv("GITHUB_REPOSITORY")
	case os.Getenv("CI_PROJECT_URL") != "":
		uri = os.Getenv("CI_PROJECT_URL")
	default:
		if remote, err := git(repoRoot, "remote", "get-url", "origin"); err == nil {
			uri = NormalizeRepoURI(remote)
		}
	}
	source := Source{URI: uri, Commit: commit, Path: path}

	// Any modified, untracked, or ignored file inside the artifact means the digest
	// would not correspond to the commit.
	dirty, err := git(repoRoot, "status", "--porcelain", "--ignored", "--untracked-files=all", "--", path)
	if err != nil {
		return Source{}, ProvenanceResult{}, err
	}
	if dirty != "" {
		return source, ProvenanceResult{Result: "fail", UnchangedFromCommit: false, Reason: "artifact has uncommitted, untracked, or ignored files"}, nil
	}
	if uri == "" {
		return source, ProvenanceResult{Result: "fail", UnchangedFromCommit: true, Reason: "no source repository URL (set an origin remote)"}, nil
	}
	return source, ProvenanceResult{Result: "pass", UnchangedFromCommit: true}, nil
}
