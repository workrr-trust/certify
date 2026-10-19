// Artifact digests (spec §1).
package certify

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type DigestAlgorithm string

const (
	AlgFileSHA256 DigestAlgorithm = "file-sha256"
	AlgDirhashV1  DigestAlgorithm = "workrr-dirhash-v1"
)

type ArtifactFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
	// abs is where the bytes live on disk (paths are decoded for the manifest).
	abs string
}

type ArtifactDigest struct {
	Algorithm DigestAlgorithm `json:"algorithm"`
	SHA256    string          `json:"sha256"`
	Files     []ArtifactFile  `json:"files"`
}

func DigestArtifact(root string) (*ArtifactDigest, error) {
	st, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if st.Mode().IsRegular() {
		b, err := os.ReadFile(root)
		if err != nil {
			return nil, err
		}
		sha := SHA256Hex(b)
		name := root[strings.LastIndexAny(root, `/\`)+1:]
		return &ArtifactDigest{
			Algorithm: AlgFileSHA256,
			SHA256:    sha,
			Files:     []ArtifactFile{{Path: name, SHA256: sha, Size: len(b), abs: root}},
		}, nil
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("Not a file or directory: %s", root)
	}

	var files []ArtifactFile
	var walk func(dir, rel string) error
	walk = func(dir, rel string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.Name() == ".git" {
				continue
			}
			abs := filepath.Join(dir, e.Name())
			// Node decodes directory entries as UTF-8 with replacement.
			name := DecodeUTF8([]byte(e.Name()))
			relPath := name
			if rel != "" {
				relPath = rel + "/" + name
			}
			switch {
			case e.Type()&os.ModeSymlink != 0:
				target, err := os.Readlink(abs)
				if err != nil {
					return err
				}
				t := DecodeUTF8([]byte(target))
				files = append(files, ArtifactFile{Path: relPath, SHA256: SHA256Hex([]byte(t)), Size: len(t), abs: abs})
			case e.IsDir():
				if err := walk(abs, relPath); err != nil {
					return err
				}
			case e.Type().IsRegular():
				b, err := os.ReadFile(abs)
				if err != nil {
					return err
				}
				files = append(files, ArtifactFile{Path: relPath, SHA256: SHA256Hex(b), Size: len(b), abs: abs})
			}
		}
		return nil
	}
	if err := walk(root, ""); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("Artifact directory is empty: %s", root)
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	var manifest strings.Builder
	for _, f := range files {
		manifest.WriteString(f.SHA256 + "  " + f.Path + "\n")
	}
	return &ArtifactDigest{Algorithm: AlgDirhashV1, SHA256: SHA256Hex([]byte(manifest.String())), Files: files}, nil
}
