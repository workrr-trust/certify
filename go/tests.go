// Reproducible test suite. The artifact declares its suite in workrr.json:
//
//	{ "test": { "command": "node test.js" } }
//
// The suite is part of the artifact, so it is covered by the artifact digest.
//
// SECURITY: this runs artifact-supplied code. In CI it must run in a job that has
// no OIDC / signing permission; the signing job only consumes the result file.
package certify

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type TestsResult struct {
	Result   string  `json:"result"`
	Command  *string `json:"command,omitempty"`
	ExitCode *int    `json:"exitCode,omitempty"`
}

// TestsReport is what the test job hands to the signing job.
type TestsReport struct {
	ArtifactDigest string      `json:"artifactDigest"`
	Tests          TestsResult `json:"tests"`
}

func ReadTestCommand(a *Artifact) string {
	if !a.IsDirectory {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(a.Root, "workrr.json"))
	if err != nil {
		return ""
	}
	var manifest struct {
		Test struct {
			Command any `json:"command"`
		} `json:"test"`
	}
	if json.Unmarshal([]byte(DecodeUTF8(b)), &manifest) != nil {
		return ""
	}
	if cmd, ok := manifest.Test.Command.(string); ok {
		return JSTrim(cmd)
	}
	return ""
}

func RunTests(a *Artifact, timeout time.Duration) TestsResult {
	command := ReadTestCommand(a)
	if command == "" {
		return TestsResult{Result: "none"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	cmd.Dir = a.Root
	cmd.Env = append(os.Environ(), "PIP_BREAK_SYSTEM_PACKAGES=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		switch {
		case errors.As(err, &exitErr) && exitErr.ExitCode() >= 0:
			code = exitErr.ExitCode()
		case errors.As(err, &exitErr):
			code = 1 // killed by a signal (incl. timeout): Node reports code null → 1
		default:
			code = 127 // could not spawn
		}
	}
	result := "fail"
	if code == 0 {
		result = "pass"
	}
	return TestsResult{Result: result, Command: &command, ExitCode: &code}
}
