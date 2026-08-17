package cli

import (
	"io/fs"
	"path/filepath"
)

// vcsMarker is the entry name that identifies a version-control checkout. A
// packaged app never carries one: release tarballs are built from a staging
// directory (e.g. build/artifacts/appstore/<app>) that holds the app payload
// only, never from the working tree.
const vcsMarker = ".git"

// findVCSMarker returns the path of the first .git entry at or under root, or ""
// when the tree carries none.
//
// Both a directory (ordinary clone) and a regular file (worktree or submodule
// gitlink) count: either one means root is a checkout rather than an app
// payload, and neither belongs in a signed app.
func findVCSMarker(root string) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() != vcsMarker {
			return nil
		}
		found = path
		return fs.SkipAll
	})
	if err != nil {
		return "", err
	}
	return found, nil
}
