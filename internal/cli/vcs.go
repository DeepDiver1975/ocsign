package cli

import (
	"io/fs"
	"path/filepath"

	"github.com/owncloud/ocsign/internal/manifest"
)

// vcsMarker is the entry name that identifies a version-control checkout. A
// packaged app never carries one: release tarballs are built from a staging
// directory (e.g. build/artifacts/appstore/<app>) that holds the app payload
// only, never from the working tree.
const vcsMarker = ".git"

// findVCSMarker returns the path of the first .git entry at or under root within
// the file set the manifest covers for mode, or "" when the tree carries none.
//
// Both a directory (ordinary clone) and a regular file (worktree or submodule
// gitlink) count, and the marker's own contents are irrelevant: an empty .git, a
// .git symlink, or one holding nothing the manifest hashes still means root is a
// working tree rather than an app payload. The marker is the evidence, not the
// harm -- the harm is the rest of that tree, the tests and CI config the
// manifest does hash. `rsync -a --exclude='.git/*'` leaves exactly that shape.
//
// Subtrees the manifest excludes for mode are skipped, because a marker there is
// no evidence of a mis-aimed --path: core mode drops whole top-level trees
// (data/, apps/, ...), and on a real server root a .git under a user's synced
// folder or a git-installed app is commonplace. Skipping them also spares the
// walk a full traversal of the data directory.
func findVCSMarker(root string, mode manifest.Mode) (string, error) {
	var found string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if manifest.ExcludesSubtree(filepath.ToSlash(rel), mode) {
				return fs.SkipDir
			}
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
