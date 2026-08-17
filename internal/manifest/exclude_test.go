package manifest_test

import (
	"testing"

	"github.com/owncloud/ocsign/internal/manifest"
)

// TestExcludesSubtree pins the directory-level predicate callers use to prune a
// walk: true only where *every* key below the directory is excluded. Core mode's
// top-level folder rule has that property; the cruft and exact-path rules do not,
// because they match a base filename or a single path.
func TestExcludesSubtree(t *testing.T) {
	cases := []struct {
		dirKey string
		mode   manifest.Mode
		want   bool
	}{
		// Core: the excluded top-level trees, at any depth below them.
		{"data", manifest.ModeCore, true},
		{"data/alice/files", manifest.ModeCore, true},
		{"apps", manifest.ModeCore, true},
		{"apps/myapp/vendor", manifest.ModeCore, true},
		{"themes", manifest.ModeCore, true},
		{"config", manifest.ModeCore, true},
		{"assets", manifest.ModeCore, true},
		{"lost+found", manifest.ModeCore, true},

		// Core: hashed territory, including the root and names that merely share a
		// prefix with an excluded one (the rule matches whole first segments).
		{".", manifest.ModeCore, false},
		{"", manifest.ModeCore, false},
		{"core", manifest.ModeCore, false},
		{"core/js", manifest.ModeCore, false},
		{"core/apps-like", manifest.ModeCore, false},
		{"database", manifest.ModeCore, false},

		// A directory whose own name is cruft still holds hashed files, so it must
		// not be pruned in either mode.
		{".directory", manifest.ModeCore, false},
		{".directory", manifest.ModeApp, false},

		// App mode prunes nothing: the core top-level exclusions do not apply, so an
		// app shipping a data/ or apps/ directory has it hashed.
		{"data", manifest.ModeApp, false},
		{"apps", manifest.ModeApp, false},
		{"appinfo", manifest.ModeApp, false},
	}

	for _, tc := range cases {
		if got := manifest.ExcludesSubtree(tc.dirKey, tc.mode); got != tc.want {
			t.Errorf("ExcludesSubtree(%q, %v) = %v, want %v", tc.dirKey, tc.mode, got, tc.want)
		}
	}
}
