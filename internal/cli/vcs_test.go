package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// signature returns the default app signature path inside tree.
func signature(tree string) string {
	return filepath.Join(tree, "appinfo", "signature.json")
}

// TestRefusesRepoCheckout: a --path holding a .git directory is a checkout, not
// an app payload -> input error, exit 1, and nothing written. This is the guard
// against the files_antivirus v1.3.1 failure, where the signed tree was the
// working copy and the manifest hashed .git/config and .git/index.
func TestRefusesRepoCheckout(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	if err := os.MkdirAll(filepath.Join(tree, ".git", "objects"), 0o755); err != nil {
		t.Fatal(err)
	}

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

// TestRefusesNestedRepoCheckout: the marker is found at any depth, so a vendored
// or submodule checkout below the app root is caught too.
func TestRefusesNestedRepoCheckout(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	if err := os.MkdirAll(filepath.Join(tree, "vendor", "dep", ".git"), 0o755); err != nil {
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

// TestRefusesRepoCheckoutOnDryRun: --dry-run writes nothing, but printing a
// manifest built from a checkout is still wrong, so the guard applies there too.
func TestRefusesRepoCheckoutOnDryRun(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	if err := os.MkdirAll(filepath.Join(tree, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

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

// TestRefusesCoreRepoCheckout: signing the core server root from a checkout is
// the same mistake, so --core is guarded identically.
func TestRefusesCoreRepoCheckout(t *testing.T) {
	tree := copyTree(t, "tree-core")
	if err := os.MkdirAll(filepath.Join(tree, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

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

// TestAllowVCSOverride: --allow-vcs signs a checkout deliberately, for the
// developer who signs an app in place to exercise verification locally.
func TestAllowVCSOverride(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	if err := os.MkdirAll(filepath.Join(tree, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

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
