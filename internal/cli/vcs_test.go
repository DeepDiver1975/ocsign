package cli_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// signature returns the default app signature path inside tree.
func signature(tree string) string {
	return filepath.Join(tree, "appinfo", "signature.json")
}

// makeCheckout turns tree into what a repository working copy looks like to the
// signer: a .git directory holding files. The two named here are the ones the
// files_antivirus v1.3.1 manifest actually hashed.
func makeCheckout(t *testing.T, tree string) {
	t.Helper()
	writeTreeFile(t, tree, ".git/config", "[core]\n\trepositoryformatversion = 0\n")
	writeTreeFile(t, tree, ".git/index", "DIRC\x00\x00\x00\x02")
}

// symlinkTo returns a symlink named "link" in a fresh temp dir pointing at
// target, skipping the test where symlinks are unavailable (unprivileged
// Windows).
func symlinkTo(t *testing.T, target string) string {
	t.Helper()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}
	return link
}

// TestRefusesRepoCheckout: a --path holding a .git directory is a checkout, not
// an app payload -> input error, exit 1, and nothing written. This is the guard
// against the files_antivirus v1.3.1 failure, where the signed tree was the
// working copy and the manifest hashed .git/config and .git/index.
func TestRefusesRepoCheckout(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	makeCheckout(t, tree)

	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(stderr, "repository checkout") {
		t.Errorf("stderr should name the cause, got %q", stderr)
	}
	if _, err := os.Stat(signature(tree)); !os.IsNotExist(err) {
		t.Error("a refused run must not write signature.json")
	}
}

// TestRefusesGitlinkFile: worktrees and submodules record .git as a regular file
// rather than a directory; it identifies a checkout just the same.
func TestRefusesGitlinkFile(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	gitlink := filepath.Join(tree, ".git")
	if err := os.WriteFile(gitlink, []byte("gitdir: /elsewhere/.git/worktrees/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1; stderr: %s", code, stderr)
	}
}

// TestRefusesEmptyMarkerDirectory: a manifest hashes files, never directories, so
// an empty .git contributes no manifest key of its own -- and is refused all the
// same. It is what `rsync -a --exclude='.git/*'` leaves behind, over a working
// tree whose tests and CI config the manifest still hashes whole. Narrowing the
// guard to markers that are themselves hashed would wave that payload through,
// which is why the refusal is phrased around the checkout, not around .git.
func TestRefusesEmptyMarkerDirectory(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	if err := os.Mkdir(filepath.Join(tree, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1; stderr: %s", code, stderr)
	}
}

// TestRefusesMarkerSymlink: relocated and shared gitdir setups make .git a
// symlink. manifest.Build never hashes a symlink (spec §3.1), so this marker
// contributes nothing either, while the working tree around it is hashed in full.
func TestRefusesMarkerSymlink(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	if err := os.Symlink("/elsewhere/repo/.git", filepath.Join(tree, ".git")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}

	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1; stderr: %s", code, stderr)
	}
}

// TestRefusesNestedRepoCheckout: the marker is found at any depth, so a vendored
// or submodule checkout below the app root is caught too.
func TestRefusesNestedRepoCheckout(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	writeTreeFile(t, tree, "vendor/dep/.git/config", "[core]\n")

	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1; stderr: %s", code, stderr)
	}
}

// TestRefusesRepoCheckoutOnDryRun: --dry-run writes nothing, but printing a
// manifest built from a checkout is still wrong, so the guard applies there too.
func TestRefusesRepoCheckoutOnDryRun(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	makeCheckout(t, tree)

	code, stdout, _ := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
		"--dry-run",
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if stdout != "" {
		t.Errorf("a refused run must print no manifest, got %q", stdout)
	}
}

// TestRefusesSymlinkedRepoCheckout: a symlinked --path must not defeat the
// guard. filepath.WalkDir does not descend into a symlinked root -- it yields the
// link and stops -- so without resolving the root first the walk sees a clean
// one-entry tree, and manifest.Build (which walks the same way) would sign an
// empty manifest.
func TestRefusesSymlinkedRepoCheckout(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	makeCheckout(t, tree)
	link := symlinkTo(t, tree)

	code, stdout, stderr := run(t,
		"--path", link,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
		"--dry-run",
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1; stdout: %s", code, stdout)
	}
	if !strings.Contains(stderr, "repository checkout") {
		t.Errorf("stderr should name the cause, got %q", stderr)
	}
}

// TestSymlinkedPathSignsRealTree is the other half of resolving the root: a
// symlinked --path over a clean tree must sign that tree's files, not an empty
// manifest that would nonetheless carry a valid signature.
func TestSymlinkedPathSignsRealTree(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	link := symlinkTo(t, tree)

	code, stdout, stderr := run(t,
		"--path", link,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
		"--dry-run",
	)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	for _, want := range []string{"appinfo/info.xml", "js/app.js", "lib/Controller/Page.php"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("manifest should hash %q through the symlink, got:\n%s", want, stdout)
		}
	}
}

// TestRefusesCoreRepoCheckout: signing the core server root from a checkout is
// the same mistake, so --core is guarded identically -- with wording that fits
// core, which has no packaged app payload to point the operator at.
func TestRefusesCoreRepoCheckout(t *testing.T) {
	tree := copyTree(t, "tree-core")
	makeCheckout(t, tree)

	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-core-leaf.crt"),
		"--core",
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1; stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "core server root") {
		t.Errorf("core refusal should name the core server root, got %q", stderr)
	}
	if strings.Contains(stderr, "appstore") {
		t.Errorf("core refusal must not advise signing an app payload, got %q", stderr)
	}
}

// TestCoreAllowsMarkerInExcludedSubtree: in core mode the manifest excludes whole
// top-level trees (apps/, data/, ...), so a .git there can never be hashed and is
// no evidence of a mis-aimed --path. Both shapes are ordinary on a live server:
// an app installed with git clone, and a user's git repo synced into their files.
// Refusing them would push operators to --allow-vcs, which would switch the guard
// off for the core tree as well.
func TestCoreAllowsMarkerInExcludedSubtree(t *testing.T) {
	tree := copyTree(t, "tree-core")
	writeTreeFile(t, tree, "apps/myapp/.git/config", "[core]\n")
	writeTreeFile(t, tree, "data/alice/files/proj/.git/config", "[core]\n")

	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-core-leaf.crt"),
		"--core",
	)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(tree, "core", "signature.json")); err != nil {
		t.Errorf("core root should sign: %v", err)
	}
}

// TestRefusesCoreMarkerInHashedSubtree pins the counterpart: outside the excluded
// top-level trees a marker is hashed, so core mode still refuses.
func TestRefusesCoreMarkerInHashedSubtree(t *testing.T) {
	tree := copyTree(t, "tree-core")
	writeTreeFile(t, tree, "core/js/.git/config", "[core]\n")

	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-core-leaf.crt"),
		"--core",
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1; stderr: %s", code, stderr)
	}
}

// TestAppModeRefusesMarkerInCoreExcludedDir: the exclusions are core-mode only.
// An app that ships an apps/ or data/ directory has it hashed, so a .git there is
// still a refusal in app mode.
func TestAppModeRefusesMarkerInCoreExcludedDir(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	writeTreeFile(t, tree, "data/.git/config", "[core]\n")

	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1; stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "the app") {
		t.Errorf("app refusal should name the app, got %q", stderr)
	}
}

// TestAllowVCSOverride: --allow-vcs signs a checkout deliberately, for the
// developer who signs an app in place to exercise verification locally.
func TestAllowVCSOverride(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	makeCheckout(t, tree)

	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
		"--allow-vcs",
	)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	if _, err := os.Stat(signature(tree)); err != nil {
		t.Errorf("--allow-vcs should sign the tree: %v", err)
	}
}

// TestCleanTreeUnaffected pins the guard's negative case: a payload with no .git
// signs exactly as before.
func TestCleanTreeUnaffected(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
	)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	if _, err := os.Stat(signature(tree)); err != nil {
		t.Errorf("clean tree should sign: %v", err)
	}
}
