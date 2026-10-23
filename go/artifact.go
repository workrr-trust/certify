// Artifact type detection (spec §2), naming, and SKILL.md frontmatter.
package certify

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

type ArtifactType string

const (
	TypeSkill        ArtifactType = "skill"
	TypeMCPServer    ArtifactType = "mcp-server"
	TypeAgentContext ArtifactType = "agent-context"
	TypeOther        ArtifactType = "other"
)

type Artifact struct {
	Root        string
	IsDirectory bool
	Name        string
	Type        ArtifactType
	Digest      *ArtifactDigest
	// Frontmatter is nil when SKILL.md has no parseable YAML mapping.
	Frontmatter      map[string]any
	SkillBody        string
	EscapingSymlinks []string
}

var winDriveRe = regexp.MustCompile(`^[a-zA-Z]:[\\/]`)

func SymlinkEscapesRoot(relPath, target string) bool {
	if target == "" || strings.HasPrefix(target, "/") || winDriveRe.MatchString(target) {
		return true
	}
	norm := strings.ReplaceAll(target, "\\", "/")
	parent := path.Dir(relPath)
	combined := norm
	if parent != "." {
		combined = parent + "/" + norm
	}
	resolved := path.Clean(combined)
	return resolved == ".." || strings.HasPrefix(resolved, "../")
}

func LoadArtifact(root string) (*Artifact, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	isDir := st.IsDir()
	digest, err := DigestArtifact(root)
	if err != nil {
		return nil, err
	}
	has := func(p string) bool {
		for _, f := range digest.Files {
			if f.Path == p {
				return true
			}
		}
		return false
	}
	single := ""
	if !isDir {
		single = jsBasename(root)
	}

	typ := TypeOther
	switch {
	case has("SKILL.md") || single == "SKILL.md":
		typ = TypeSkill
	case has("server.json"):
		typ = TypeMCPServer
	case has("AGENTS.md") || has("CLAUDE.md") || single == "AGENTS.md" || single == "CLAUDE.md":
		typ = TypeAgentContext
	}

	a := &Artifact{Root: root, IsDirectory: isDir, Name: jsBasename(root), Type: typ, Digest: digest}
	switch typ {
	case TypeSkill:
		p := root
		if isDir {
			p = filepath.Join(root, "SKILL.md")
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		text := DecodeUTF8(b)
		a.SkillBody = StripFrontmatter(text)
		a.Frontmatter = ParseFrontmatter(text)
		if n, ok := a.Frontmatter["name"].(string); ok && n != "" {
			a.Name = n
		}
	case TypeMCPServer:
		// Unparseable server.json: keep the directory name; policy reports it.
		if b, err := os.ReadFile(filepath.Join(root, "server.json")); err == nil {
			var server any
			if json.Unmarshal([]byte(DecodeUTF8(b)), &server) == nil {
				if m, ok := server.(map[string]any); ok {
					if n, ok := m["name"].(string); ok && n != "" {
						a.Name = n
					}
				}
			}
		}
	}
	for _, f := range digest.Files {
		if f.symlinkTarget != nil && SymlinkEscapesRoot(f.Path, *f.symlinkTarget) {
			a.EscapingSymlinks = append(a.EscapingSymlinks, f.Path)
		}
	}
	return a, nil
}

// Same expression as the TypeScript reference; RE2 handles it unchanged.
var frontmatterRe = regexp.MustCompile("^\uFEFF?---\\r?\\n([\\s\\S]*?)\\r?\\n---(?:\\r?\\n)?")

func StripFrontmatter(text string) string {
	loc := frontmatterRe.FindStringIndex(text)
	if loc == nil {
		return text
	}
	return text[loc[1]:]
}

// ParseFrontmatter returns the YAML mapping between the leading `---` fences.
// A YAML sequence counts as parseable but has no fields (JavaScript arrays are
// objects); scalars, null, and parse errors yield nil.
func ParseFrontmatter(text string) map[string]any {
	m := frontmatterRe.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(m[1]), &doc); err != nil || doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	parsed, err := yamlToJS(doc.Content[0])
	if err != nil {
		return nil
	}
	switch v := parsed.(type) {
	case map[string]any:
		return v
	case []any:
		return map[string]any{}
	}
	return nil
}

// yamlBinary is a !!binary scalar: an object (Buffer) in JavaScript, not a string.
type yamlBinary []byte

// YAML 1.2 core schema, as resolved by the npm `yaml` package the reference
// uses. yaml.v3's own resolution differs (it reads 012 as octal, applies `<<`
// merge keys, and decodes !!binary to a string), so scalars are resolved here.
var (
	yamlNullRe    = regexp.MustCompile(`^(?:~|[Nn]ull|NULL)?$`)
	yamlTrueRe    = regexp.MustCompile(`^(?:[Tt]rue|TRUE)$`)
	yamlFalseRe   = regexp.MustCompile(`^(?:[Ff]alse|FALSE)$`)
	yamlOctRe     = regexp.MustCompile(`^0o[0-7]+$`)
	yamlIntRe     = regexp.MustCompile(`^[-+]?[0-9]+$`)
	yamlHexRe     = regexp.MustCompile(`^0x[0-9a-fA-F]+$`)
	yamlInfRe     = regexp.MustCompile(`^[-+]?\.(?:inf|Inf|INF)$`)
	yamlNaNRe     = regexp.MustCompile(`^\.(?:nan|NaN|NAN)$`)
	yamlExpRe     = regexp.MustCompile(`^[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+$`)
	yamlFloatRe   = regexp.MustCompile(`^[-+]?(?:\.[0-9]+|[0-9]+\.[0-9]*)$`)
	errYAMLDupKey = errors.New("yaml: map keys must be unique")
)

func yamlToJS(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.AliasNode:
		return yamlToJS(n.Alias)
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := yamlToJS(c)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, err := yamlToJS(n.Content[i])
			if err != nil {
				return nil, err
			}
			v, err := yamlToJS(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			key := ""
			if k != nil {
				key = JSString(k)
			}
			if _, dup := out[key]; dup {
				return nil, errYAMLDupKey
			}
			out[key] = v
		}
		return out, nil
	case yaml.ScalarNode:
		return yamlScalar(n)
	}
	return nil, nil
}

func yamlScalar(n *yaml.Node) (any, error) {
	v := n.Value
	tag := ""
	if n.Style&yaml.TaggedStyle != 0 {
		tag = n.ShortTag()
	} else if n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return v, nil
	}
	switch tag {
	case "!!str":
		return v, nil
	case "!!binary":
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v), ""))
		if err != nil {
			return nil, err
		}
		return yamlBinary(b), nil
	case "", "!!null", "!!bool", "!!int", "!!float":
	default:
		return v, nil // unknown tags resolve to the plain string
	}
	switch {
	case yamlNullRe.MatchString(v):
		return nil, nil
	case yamlTrueRe.MatchString(v):
		return true, nil
	case yamlFalseRe.MatchString(v):
		return false, nil
	case yamlOctRe.MatchString(v):
		i, _ := strconv.ParseUint(v[2:], 8, 64)
		return float64(i), nil
	case yamlIntRe.MatchString(v), yamlExpRe.MatchString(v), yamlFloatRe.MatchString(v):
		f, _ := strconv.ParseFloat(v, 64) // ±Inf on overflow, as Number() gives
		return f, nil
	case yamlHexRe.MatchString(v):
		i, _ := strconv.ParseUint(v[2:], 16, 64)
		return float64(i), nil
	case yamlInfRe.MatchString(v):
		if v[0] == '-' {
			return math.Inf(-1), nil
		}
		return math.Inf(1), nil
	case yamlNaNRe.MatchString(v):
		return math.NaN(), nil
	}
	return v, nil
}

// jsBasename is Node's path.posix.basename.
func jsBasename(p string) string {
	p = strings.TrimRight(p, "/")
	return p[strings.LastIndex(p, "/")+1:]
}
