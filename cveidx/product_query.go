package cveidx

import (
	"regexp"
	"strings"
)

// Only split an explicit, whitespace-separated trailing version. Digits inside
// product names (http2, log4j, thinkphp6) are identities, not version ranges.
var productVersionSuffix = regexp.MustCompile(`(?i)^(.*\S)\s+(v?[0-9]+(?:\.[0-9]+)*(?:[-+][0-9a-z][0-9a-z.-]*)?)$`)

// SplitProductVersion keeps the original version for context; search candidates
// remain product-level, not a claim that any template applies to that version.
func SplitProductVersion(query string) (product, version string) {
	query = strings.TrimSpace(query)
	if m := productVersionSuffix.FindStringSubmatch(query); m != nil {
		return strings.TrimSpace(m[1]), m[2]
	}
	return query, ""
}
