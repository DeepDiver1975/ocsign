package manifest

import (
	"regexp"
	"strings"
)

// appSignatureFile is the app-mode signature file, excluded from its own
// manifest (spec §3.2 item 1).
const appSignatureFile = "appinfo/signature.json"

// Core-mode exclusions by exact relative path (spec §3.6): the core signature
// file and the regeneratable mimetype list.
const (
	coreSignatureFile = "core/signature.json"
	mimetypeListFile  = "core/js/mimetypelist.js"
)

// coreTopLevelExcludedDirs are the server-root top-level directories the legacy
// verifier's ExcludeFoldersByPathFilterIterator skips. Matched on the first path
// segment only. The legacy iterator additionally excludes the runtime custom
// datadir and dynamic app roots, which a standalone signer cannot know; only
// this static list is transcribable.
var coreTopLevelExcludedDirs = map[string]struct{}{
	"data":       {},
	"themes":     {},
	"config":     {},
	"apps":       {},
	"assets":     {},
	"lost+found": {},
}

// cruftBaseNames are OS / file-manager artifacts excluded by exact base filename
// in any directory (spec §3.2 item 2). They are created at rest, never by the app.
var cruftBaseNames = map[string]struct{}{
	".DS_Store":  {}, // macOS
	"Thumbs.db":  {}, // Windows
	".directory": {}, // KDE Dolphin
	".webapp":    {}, // Gentoo webapp-config
}

// cruftPattern matches Gentoo webapp-config markers by base filename (spec §3.2
// item 3).
var cruftPattern = regexp.MustCompile(`^\.webapp-owncloud-.*`)

// ExcludesSubtree reports whether every manifest key under the directory dirKey
// (a forward-slash relative path, "." for the root) is excluded for mode, so a
// walker may skip the directory wholesale.
//
// Only core mode's top-level folder exclusion has that property. The cruft rules
// match base filenames, so a directory whose own name is cruft (e.g. a directory
// literally called .directory) still holds files that are hashed, and the exact
// path exclusions cover single files.
func ExcludesSubtree(dirKey string, mode Mode) bool {
	if mode != ModeCore || dirKey == "" || dirKey == "." {
		return false
	}
	top := dirKey
	if i := strings.IndexByte(dirKey, '/'); i >= 0 {
		top = dirKey[:i]
	}
	_, ok := coreTopLevelExcludedDirs[top]
	return ok
}

// isExcluded reports whether the manifest key (a forward-slash relative path)
// must be excluded from the manifest for the given mode (§3.2 app, §3.6 core).
func isExcluded(key string, mode Mode) bool {
	// OS/file-manager cruft is excluded identically in both modes (§3.2 items
	// 2–3, shared with core via §3.6).
	base := key
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		base = key[i+1:]
	}
	if _, ok := cruftBaseNames[base]; ok {
		return true
	}
	if cruftPattern.MatchString(base) {
		return true
	}

	if mode == ModeCore {
		// The legacy Checker::generateHashes excludes both signature files
		// unconditionally, so a stray appinfo/signature.json in the server root
		// is excluded in core mode too, matching the verifier.
		if key == coreSignatureFile || key == appSignatureFile || key == mimetypeListFile {
			return true
		}
		// Top-level folder exclusion on the first path segment only, so
		// apps/foo.php is excluded but core/apps-like/x.php is kept. Shared with
		// ExcludesSubtree so the manifest and its callers cannot disagree about
		// which trees are excluded.
		return ExcludesSubtree(key, mode)
	}

	return key == appSignatureFile
}
