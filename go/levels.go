package certify

import "strings"

// Level names say how much scrutiny an artifact got (src/levels.ts). The wire
// values in signed predicates are unchanged: scanned, banded, silver, gold.
var LevelNames = map[string]string{
	"scanned": "Scanned",
	"banded":  "Signed",
	"silver":  "Tested",
	"gold":    "Reproduced",
}

var levelAliases = map[string]string{
	"scanned": "scanned", "banded": "banded", "signed": "banded",
	"silver": "silver", "tested": "silver", "gold": "gold", "reproduced": "gold",
}

// LevelName is the display name for a wire level, or "" if unknown.
func LevelName(level string) string { return LevelNames[level] }

// ParseLevel accepts a display name or a wire value, any case; "" if unknown.
func ParseLevel(input string) string { return levelAliases[strings.ToLower(strings.TrimSpace(input))] }
