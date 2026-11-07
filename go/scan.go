// Known-pattern scan. A pass means "no high or critical findings from this ruleset",
// never "safe". The ruleset is data so its digest pins exactly what ran.
//
// The Rule records below are byte-for-byte the TypeScript reference's: they are
// the digest input, and the patterns are ECMAScript regular expressions. Go's RE2
// differs from ECMAScript, so each rule is executed by a Go matcher that
// reproduces the ECMAScript semantics exactly:
//
//   - Rules without the `u` flag run over CodeUnitString(text), where every UTF-16
//     code unit is one rune, so bounded repeats like [^\n]{0,40} count what
//     JavaScript counts (an emoji is two units).
//   - `\s` becomes JavaScript's whitespace set (Unicode spaces, \v, U+FEFF); RE2's
//     \s is ASCII-only.
//   - The `i` flag becomes explicit ASCII case classes ([iI]). Non-unicode
//     ECMAScript case folding never maps non-ASCII to ASCII, whereas RE2's (?i)
//     would let U+212A KELVIN SIGN match `k` and U+017F LONG S match `s`.
//   - WT004 uses a lookbehind and WT008 a lookahead plus a {0,2000} repeat, which
//     RE2 lacks (and caps repeats at 1000). Both are hand-written matchers below.
//   - The reference adds the `m` flag to every rule; only WT004's `^` is affected.
package certify

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

type Severity string

type Rule struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Pattern     string   `json:"pattern"`
	Flags       string   `json:"flags"`
	// Also holds patterns that must each match somewhere in the same file.
	Also []string `json:"also,omitempty"`
	// Origin says where a rule came from, when it isn't workrr's own.
	Origin string `json:"origin,omitempty"`
}

const RulesetVersion = "workrr-scan-v0.3"

var Rules = []Rule{
	{ID: "WT001", Severity: "high", Description: "Instruction override phrasing",
		Pattern: "\\b(ignore|disregard|forget)\\s+(all\\s+|any\\s+)?(previous|prior|above|earlier|preceding)\\s+(instructions|prompts|rules|directions)", Flags: "gi"},
	{ID: "WT002", Severity: "critical", Description: "Unicode tag characters (invisible ASCII smuggling)",
		Pattern: "[\\u{E0000}-\\u{E007F}]", Flags: "gu"},
	{ID: "WT003", Severity: "high", Description: "Bidirectional control characters (Trojan Source)",
		Pattern: "[\u202A-\u202E\u2066-\u2069]", Flags: "gu"},
	{ID: "WT004", Severity: "warn", Description: "Zero-width characters",
		Pattern: "[\u200B\u200C\u2060]|(?<!^)\uFEFF", Flags: "gu"},
	{ID: "WT005", Severity: "high", Description: "Remote script piped to a shell",
		Pattern: "\\b(curl|wget)\\b[^\\n|]*\\|\\s*(sudo\\s+)?(ba|z|da)?sh\\b", Flags: "gi"},
	{ID: "WT006", Severity: "high", Description: "Reads credential stores",
		Pattern: "(~|\\$HOME)?/?\\.(ssh/(id_[a-z0-9]+|authorized_keys)|aws/credentials|netrc|git-credentials|docker/config\\.json|kube/config)\\b", Flags: "gi"},
	{ID: "WT007", Severity: "high", Description: "Instructs concealment from the user",
		Pattern: "\\b(do\\s+not|don't|never)\\s+(tell|inform)\\s+the\\s+(user|human|operator)\\s+(about|that)\\b|\\b(do\\s+not|don't|never)\\s+(mention|reveal|disclose)\\b[^\\n]{0,40}\\bto\\s+the\\s+(user|human|operator)\\b", Flags: "gi"},
	{ID: "WT008", Severity: "high", Description: "Hidden HTML comment carrying instructions",
		Pattern: "<!--(?:(?!-->)[\\s\\S]){0,2000}?" + wt008Phrase + "[\\s\\S]*?-->", Flags: "gi"},
	{ID: "WT009", Severity: "warn", Description: "Sends data to a URL",
		Pattern: "\\b(post|send|upload|exfiltrate|forward)\\b[^\\n]{0,60}https?://", Flags: "gi"},
	{ID: "WT010", Severity: "warn", Description: "Large encoded blob",
		Pattern: "[A-Za-z0-9+/]{240,}={0,2}", Flags: "g"},
	{ID: "WT011", Severity: "high", Description: "Collects all environment variables and sends data out",
		Pattern: "os\\.environ\\.items\\(\\)|json\\.dumps\\(dict\\(os\\.environ\\)|JSON\\.stringify\\(process\\.env\\)", Flags: "g",
		Also:   []string{"\\b(requests|httpx)\\.(post|put)\\(|\\baxios\\.post\\("},
		Origin: "SkillSpector E1 and E2 (NVIDIA, Apache-2.0), commit 54824463, adapted 2026-11-07"},
	{ID: "WT012", Severity: "high", Description: "Instructs adding a poison, or self-harm",
		Pattern: "\\b(add\\s+(a\\s+)?(dash|pinch|bit|drop|amount)\\s+of\\s+|(include|incorporate|mix\\s+in|stir\\s+in)\\s+(some\\s+)?)(cyanide|arsenic|ricin|botulinum|strychnine|thallium|polonium|sarin|vx gas|mustard gas|anthrax|deadly nightshade|aconite|hemlock|oleander)\\b|\\b(you\\s+should|try\\s+to|please)\\s+(hurt|harm|injure)\\s+yourself\\b", Flags: "gi",
		Origin: "SkillSpector P5 (NVIDIA, Apache-2.0), commit 54824463, adapted 2026-11-07"},
	{ID: "WT013", Severity: "high", Description: "Sends or saves the system prompt through a tool",
		Pattern: "\\b(write|save|store|log|dump|send|post|upload|transmit|copy|pipe|forward)\\s+(your\\s+(system\\s+)?(prompt|instructions)|(the\\s+)?system\\s+prompt)\\s+(to|into|via|through)\\s+(https?://|external|remote|webhook|server|curl|wget)", Flags: "gi",
		Origin: "SkillSpector P8 (NVIDIA, Apache-2.0), commit 54824463, adapted 2026-11-07"},
	{ID: "WT014", Severity: "high", Description: "Mining protocol or known mining pool",
		Pattern: "stratum\\+(tcp|ssl)://|\\bmining\\.(subscribe|authorize|submit)\\b|\\b(pool\\.minexmr\\.com|xmrpool\\.eu|monerohash\\.com|supportxmr\\.com|nanopool\\.org|hashvault\\.pro|herominers\\.com|unmineable\\.com|minergate\\.com)\\b", Flags: "gi",
		Origin: "SkillSpector YARA crypto_stratum_protocol and crypto_mining_pools (NVIDIA, Apache-2.0), commit 54824463, adapted 2026-11-07; based on Neo23x0/signature-base (Detection Rule License 1.1)"},
	{ID: "WT015", Severity: "high", Description: "Mining software configured to run",
		Pattern: "\\b(xmrig|xmr-stak|cpuminer|cgminer|bfgminer|ethminer|nbminer|phoenixminer)\\b", Flags: "gi",
		Also:   []string{"--donate-level|--pool\\b|\\bwallet\\b|\\bhashrate\\b"},
		Origin: "SkillSpector YARA crypto_miner_software (NVIDIA, Apache-2.0), commit 54824463, adapted 2026-11-07; based on Neo23x0/signature-base (Detection Rule License 1.1)"},
	{ID: "WT016", Severity: "critical", Description: "Browser cryptojacking script",
		Pattern: "coinhive\\.min\\.js|CoinHive\\.Anonymous\\s*\\(|\\bcryptoloot\\b|webmine\\.pro|\\bjsecoin\\b|\\bcoin-imp\\b|minero\\.cc|\\bmonerominer\\b", Flags: "gi",
		Origin: "SkillSpector YARA crypto_coinjacking (NVIDIA, Apache-2.0), commit 54824463, adapted 2026-11-07; based on Neo23x0/signature-base (Detection Rule License 1.1)"},
	{ID: "WT017", Severity: "critical", Description: "PHP webshell: runs request input or decoded payloads",
		Pattern: "\\b(eval|assert|system|passthru|shell_exec|popen|proc_open)\\s*\\(\\s*\\$_(POST|GET|REQUEST|COOKIE)\\s*\\[|\\beval\\s*\\(\\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\\s*\\(", Flags: "gi",
		Origin: "SkillSpector YARA php_webshell_generic and php_webshell_obfuscated (NVIDIA, Apache-2.0), commit 54824463, adapted 2026-11-07; based on Neo23x0/signature-base (Detection Rule License 1.1)"},
	{ID: "WT018", Severity: "critical", Description: "Known webshell family",
		Pattern: "\\b(c99shell|c99_sess_put|r57shell|b374k|p0wny|GodzillaShell)\\b|Web Shell by oRb", Flags: "gi",
		Origin: "SkillSpector YARA php_webshell_known (NVIDIA, Apache-2.0), commit 54824463, adapted 2026-11-07; based on Neo23x0/signature-base (Detection Rule License 1.1)"},
	{ID: "WT019", Severity: "high", Description: "Python, JSP or ASPX code runs request input",
		Pattern: "[^.a-zA-Z0-9_](exec|eval)\\s*\\(\\s*request\\.|\\bos\\.(popen|system)\\s*\\(\\s*request\\.|\\bsubprocess\\.[a-zA-Z0-9_]+\\s*\\(\\s*request\\.|Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(\\s*request\\.getParameter|ProcessBuilder\\s*\\([^\\n]*request\\.getParameter|Process\\.Start\\s*\\([^\\n]*Request\\[|cmd\\.exe[^\\n]*Request\\.", Flags: "gi",
		Origin: "SkillSpector YARA python_webshell, jsp_webshell and aspx_webshell (NVIDIA, Apache-2.0), commit 54824463, adapted 2026-11-07; based on Neo23x0/signature-base (Detection Rule License 1.1)"},
	{ID: "WT020", Severity: "critical", Description: "Reverse shell",
		Pattern: "\\bbash\\s+-i\\s+>&\\s*/dev/tcp/|\\bncat?\\s[^\\n]*-e\\s*/bin/(ba)?sh\\b|\\bsocat\\s[^\\n]*EXEC[^\\n]*/bin/(ba)?sh|\\bmkfifo\\s[^\\n]*\\|\\s*/bin/(ba)?sh|\\bfsockopen\\s*\\([^\\n]*\\bexec\\s*\\(", Flags: "gi",
		Origin: "SkillSpector YARA reverse_shell (NVIDIA, Apache-2.0), commit 54824463, adapted 2026-11-07; based on Neo23x0/signature-base (Detection Rule License 1.1)"},
	{ID: "WT021", Severity: "high", Description: "Backdoor persistence",
		Pattern: "\\buseradd\\s[^\\n]*-o\\s+-u\\s+0\\b|\\becho\\s[^\\n]*>>?\\s*[^\\n]*\\.ssh/authorized_keys|\\becho\\s[^\\n]*(curl|wget|base64|/dev/tcp)[^\\n]*>>\\s*[^\\n]*\\.(bashrc|profile)\\b", Flags: "gi",
		Origin: "SkillSpector YARA backdoor_persistence (NVIDIA, Apache-2.0), commit 54824463, adapted 2026-11-07; based on Neo23x0/signature-base (Detection Rule License 1.1)"},
	{ID: "WT022", Severity: "critical", Description: "Ransomware behavior",
		Pattern: "os\\.walk\\s*\\([^\\n]*\\.(encrypt|cipher)\\b|os\\.rename\\s*\\([^\\n]*\\+\\s*['\"]\\.(locked|encrypted|crypt|enc)['\"]\\s*\\)", Flags: "gi",
		Origin: "SkillSpector YARA ransomware_behavior (NVIDIA, Apache-2.0), commit 54824463, adapted 2026-11-07; based on Neo23x0/signature-base (Detection Rule License 1.1)"},
}

// RulesetDigest is jsonDigest({version, rules}).
func RulesetDigest() string {
	d, err := JSONDigest(map[string]any{"version": RulesetVersion, "rules": Rules})
	if err != nil {
		panic(err)
	}
	return d
}

type ScanException struct {
	Rule       string `json:"rule"`
	File       string `json:"file"`
	Line       *int   `json:"line,omitempty"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approvedBy,omitempty"`
}

type Finding struct {
	Rule            string   `json:"rule"`
	Severity        Severity `json:"severity"`
	File            string   `json:"file"`
	Line            int      `json:"line"`
	Excepted        bool     `json:"excepted,omitempty"`
	ExceptionReason string   `json:"exceptionReason,omitempty"`
}

type ScanResult struct {
	Result         string          `json:"result"`
	RulesetVersion string          `json:"rulesetVersion"`
	RulesetDigest  string          `json:"rulesetDigest"`
	Findings       []Finding       `json:"findings"`
	Exceptions     []ScanException `json:"exceptions,omitempty"`
}

// A matcher returns the start offsets of every match, in order, as JavaScript's
// String#matchAll would, plus the string those offsets index (for line counting).
type matcher func(text string) (subject string, starts []int)

var matchers = func() map[string]matcher {
	m := map[string]matcher{
		"WT004": matchWT004,
		"WT008": matchWT008,
	}
	for _, r := range Rules {
		if _, custom := m[r.ID]; custom {
			continue
		}
		unicodeMode := strings.Contains(r.Flags, "u")
		fold := strings.Contains(r.Flags, "i")
		re := regexp.MustCompile(translateRegExp(r.Pattern, fold, unicodeMode))
		var also []*regexp.Regexp
		for _, p := range r.Also {
			also = append(also, regexp.MustCompile(translateRegExp(p, fold, unicodeMode)))
		}
		m[r.ID] = func(text string) (string, []int) {
			if !unicodeMode {
				text = CodeUnitString(text)
			}
			for _, a := range also {
				if !a.MatchString(text) {
					return text, nil
				}
			}
			var starts []int
			for _, loc := range re.FindAllStringIndex(text, -1) {
				starts = append(starts, loc[0])
			}
			return text, starts
		}
	}
	return m
}()

var (
	evalFixturePathRe    = regexp.MustCompile(`(^|/)(evals|test|tests|fixtures)/`)
	defensiveWT001LineRe = regexp.MustCompile(`\b(` + asciiFold("never") + `[` + JSWhitespaceClass + `]+` + asciiFold("follow") +
		`|` + asciiFold("not") + `[` + JSWhitespaceClass + `]+` + asciiFold("a") + asciiFold("n") + `?[` + JSWhitespaceClass + `]+` + asciiFold("instruction") +
		`|` + asciiFold("neither") + `[` + JSWhitespaceClass + `]+` + asciiFold("a") + asciiFold("n") + `?[` + JSWhitespaceClass + `]+` + asciiFold("instruction") +
		`|` + asciiFold("prompt") + `[- ]` + asciiFold("injection") +
		`|` + asciiFold("untrusted") + `[` + JSWhitespaceClass + `]+` + asciiFold("data") + `)\b`)
)

// promptRules are about text an agent reads as instructions, or match malware
// samples. Tests, fixtures and snapshots are not loaded as instructions (and are
// where scanners and sanitizers keep their samples), so these rules skip them.
// Shell, credential and character rules do not.
var (
	promptRules = func() []string {
		ids := []string{"WT001", "WT007", "WT008"}
		for _, r := range Rules {
			if r.Origin != "" {
				ids = append(ids, r.ID)
			}
		}
		return ids
	}()
	TestPathRe = regexp.MustCompile(`(^|/)(test|tests|__tests__|fixtures|__snapshots__)/|(^|/)test[_-][^/]*$|[._](test|spec)\.[A-Za-z0-9]+$|\.(snap|snapshot)$`)
)

// prev is the code unit just before the match (-1 at the start of a line).
func isDefensiveExample(ruleID, file, lineText string, colBytes int, prev rune) bool {
	if slices.Contains(promptRules, ruleID) && TestPathRe.MatchString(file) {
		return true
	}
	// A quoted phrase is an example being discussed, not an instruction.
	if ruleID == "WT007" && (prev == '"' || prev == '\'' || prev == '`' || prev == 0x201C) {
		return true
	}
	if ruleID != "WT001" {
		return false
	}
	if evalFixturePathRe.MatchString(file) && strings.HasSuffix(file, ".json") {
		return true
	}
	if !defensiveWT001LineRe.MatchString(lineText) {
		return false
	}
	before := lineText
	if colBytes >= 0 && colBytes <= len(lineText) {
		before = lineText[:colBytes]
	}
	return strings.ContainsAny(before, "\"'\u201c")
}

func ScanArtifact(a *Artifact, exceptions ...[]ScanException) ScanResult {
	findings := []Finding{}
	for _, f := range a.Digest.Files {
		if slices.Contains(a.EscapingSymlinks, f.Path) {
			continue
		}
		p := a.Root
		if a.IsDirectory {
			p = f.abs
		}
		b, err := os.ReadFile(p) // follows symlinks, as readFile does
		if err != nil || slices.Contains(b, 0) {
			continue // unreadable, binary, or dangling symlink
		}
		findings = append(findings, ScanText(DecodeUTF8(b), f.Path)...)
	}
	// File (UTF-8 byte order), then line, then rule id.
	slices.SortStableFunc(findings, func(a, b Finding) int {
		if c := strings.Compare(a.File, b.File); c != 0 {
			return c
		}
		if a.Line != b.Line {
			return a.Line - b.Line
		}
		return strings.Compare(a.Rule, b.Rule)
	})
	var applied []ScanException
	if len(exceptions) > 0 && len(exceptions[0]) > 0 {
		exList := exceptions[0]
		for i := range findings {
			f := &findings[i]
			for _, ex := range exList {
				if ex.Rule == f.Rule && ex.File == f.File && (ex.Line == nil || *ex.Line == f.Line) {
					f.Excepted = true
					f.ExceptionReason = ex.Reason
					if !slices.ContainsFunc(applied, func(a ScanException) bool {
						return a.Rule == ex.Rule && a.File == ex.File && a.Reason == ex.Reason && ((a.Line == nil && ex.Line == nil) || (a.Line != nil && ex.Line != nil && *a.Line == *ex.Line))
					}) {
						applied = append(applied, ex)
					}
					break
				}
			}
		}
	}
	result := "pass"
	for _, f := range findings {
		if f.Severity != "warn" && !f.Excepted {
			result = "fail"
		}
	}
	return ScanResult{Result: result, RulesetVersion: RulesetVersion, RulesetDigest: RulesetDigest(), Findings: findings, Exceptions: applied}
}

// ScanText reports at most one finding per rule per line (the line of the match start).
func ScanText(text, file string) []Finding {
	var out []Finding
	lines := strings.Split(text, "\n")
	for _, r := range Rules {
		subject, starts := matchers[r.ID](text)
		seen := map[int]bool{}
		for _, s := range starts {
			prefix := subject[:s]
			lineIdx := strings.Count(prefix, "\n")
			line := lineIdx + 1
			if seen[line] {
				continue
			}
			lastNL := strings.LastIndex(prefix, "\n")
			col := s
			if lastNL >= 0 {
				col = s - lastNL - 1
			}
			lineText := ""
			if lineIdx < len(lines) {
				lineText = lines[lineIdx]
			}
			prev := rune(-1)
			if col > 0 {
				prev, _ = utf8.DecodeLastRuneInString(prefix)
			}
			if isDefensiveExample(r.ID, file, lineText, col, prev) {
				continue
			}
			seen[line] = true
			out = append(out, Finding{Rule: r.ID, Severity: r.Severity, File: file, Line: line})
		}
	}
	return out
}

// WT004 `[\u200B\u200C\u2060]|(?<!^)\uFEFF` with flags "gum": any zero-width
// space/non-joiner/word-joiner, or a BOM that is not at the start of a line
// (multiline `^`: start of input or after \n, \r, U+2028, U+2029).
func matchWT004(text string) (string, []int) {
	var starts []int
	prev := rune(-1)
	for i, r := range text {
		switch r {
		case 0x200B, 0x200C, 0x2060:
			starts = append(starts, i)
		case 0xFEFF:
			if prev != -1 && prev != '\n' && prev != '\r' && prev != 0x2028 && prev != 0x2029 {
				starts = append(starts, i)
			}
		}
		prev = r
	}
	return text, starts
}

// wt008Phrase is WT008's phrase group: instruction-override wording, "you are
// now", "exfiltrate", or an instruction to keep something from the user.
const wt008Phrase = "(\\b(ignore|disregard|forget)\\s+(all\\s+|any\\s+)?(previous|prior|above|earlier|preceding)\\s+(instructions|prompts|rules|directions)|\\byou\\s+are\\s+now\\b|\\bexfiltrate\\b|\\b(do\\s+not|don't|never)\\s+(tell|inform)\\s+the\\s+(user|human|operator)\\b)"

var wt008PhraseRe = regexp.MustCompile(translateRegExp(wt008Phrase, true, false))

// WT008 `<!--(?:(?!-->)[\s\S]){0,2000}?(phrase)[\s\S]*?-->` with flags "gim",
// over UTF-16 code units. From each `<!--`, the lazy repeat may consume at most
// 2000 units and none may begin `-->`, so the phrase must start within 2000 units
// of the opener and before the comment's first `-->`; a phrase never contains
// `-->`, so it also ends there, and the match ends at that `-->`. The earliest
// phrase start is RE2's leftmost match over the comment body (phrase alternatives
// only need to exist at a position, so order does not matter). The next search
// resumes at the match end, as matchAll does.
func matchWT008(text string) (string, []int) {
	subject := CodeUnitString(text)
	// unitByte[i] = byte offset in subject of code unit i (one rune per unit).
	unitByte := make([]int, 0, len(subject)+1)
	for i := range subject {
		unitByte = append(unitByte, i)
	}
	n := len(unitByte)
	unitByte = append(unitByte, len(subject))
	var starts []int
	for s := 0; s+4 <= n; {
		body := subject[unitByte[s]:]
		if !strings.HasPrefix(body, "<!--") {
			s++
			continue
		}
		bodyStart := s + 4
		closeAt := strings.Index(subject[unitByte[bodyStart]:], "-->")
		if closeAt < 0 {
			s++
			continue
		}
		inner := subject[unitByte[bodyStart] : unitByte[bodyStart]+closeAt]
		if loc := wt008PhraseRe.FindStringIndex(inner); loc != nil && utf8.RuneCountInString(inner[:loc[0]]) <= 2000 {
			starts = append(starts, unitByte[s])
			s = bodyStart + utf8.RuneCountInString(inner) + 3
			continue
		}
		s++
	}
	return subject, starts
}

// translateRegExp rewrites the ECMAScript subset used by the ruleset into RE2.
// It panics on any construct outside that subset, so a ruleset change cannot
// silently run with different semantics.
func translateRegExp(p string, fold, unicodeMode bool) string {
	rs := []rune(p)
	var sb strings.Builder
	inClass := false
	foldRune := func(r rune) string {
		switch {
		case fold && r >= 'a' && r <= 'z':
			return "[" + string(r) + string(r-32) + "]"
		case fold && r >= 'A' && r <= 'Z':
			return "[" + string(r+32) + string(r) + "]"
		}
		return string(r)
	}
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '\\':
			i++
			c := rs[i]
			switch {
			case c == 's':
				if inClass {
					sb.WriteString(JSWhitespaceClass)
				} else {
					sb.WriteString("[" + JSWhitespaceClass + "]")
				}
			case c == 'u' && unicodeMode && i+1 < len(rs) && rs[i+1] == '{':
				end := slices.Index(rs[i:], '}') + i
				sb.WriteString(`\x` + string(rs[i+1:end+1]))
				i = end
			case strings.ContainsRune(`bn.$|\()[]+`, c):
				sb.WriteRune('\\')
				sb.WriteRune(c)
			default:
				panic(fmt.Sprintf("translateRegExp: unsupported escape \\%c in %q", c, p))
			}
		case inClass:
			if r == ']' {
				inClass = false
				sb.WriteRune(r)
				continue
			}
			// Range a-z under the i flag also admits A-Z, and vice versa.
			if i+2 < len(rs) && rs[i+1] == '-' && rs[i+2] != ']' {
				lo, hi := r, rs[i+2]
				sb.WriteString(string(lo) + "-" + string(hi))
				if fold && lo >= 'a' && hi <= 'z' {
					sb.WriteString(string(lo-32) + "-" + string(hi-32))
				} else if fold && lo >= 'A' && hi <= 'Z' {
					sb.WriteString(string(lo+32) + "-" + string(hi+32))
				}
				i += 2
				continue
			}
			if f := foldRune(r); len(f) > 1 {
				sb.WriteString(f[1:3])
			} else {
				sb.WriteRune(r)
			}
		case r == '[':
			inClass = true
			sb.WriteRune(r)
			if i+1 < len(rs) && rs[i+1] == '^' {
				sb.WriteRune('^')
				i++
			}
		case r == '(' && i+1 < len(rs) && rs[i+1] == '?':
			panic(fmt.Sprintf("translateRegExp: unsupported group in %q", p))
		default:
			sb.WriteString(foldRune(r))
		}
	}
	return sb.String()
}

// asciiFold applies the `i` flag's ASCII-only case folding to a literal pattern.
func asciiFold(p string) string { return translateRegExp(p, true, false) }
