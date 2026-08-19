# ocsign

A standalone, cross-platform Go CLI that produces a `signature.json` (schema v2)
for an ownCloud app. It is **decoupled from the server** — unlike the legacy
`occ integrity:sign-app`, it needs no bootstrapped ownCloud instance.

`ocsign` does three things:

1. Walks an app (or core server root) tree and builds the **canonical file-hash
   manifest**.
2. Signs the canonical manifest bytes with the developer's private key and writes
   `appinfo/signature.json` (or `core/signature.json` with `--core`) with the
   embedded leaf certificate and chain.
3. *(Planned)* Optionally attaches a Mode-2 attestation token (`--attest`).

The manifest `ocsign` signs is **byte-identical** to what the ownCloud core
verifier recomputes. The canonicalization rules and the golden test vectors under
`testdata/` are the shared conformance artifact for both implementations.

## Status

Mode-1 signing is implemented for both **app** and **core** scopes.

- `--core` signs the core server root: it writes `core/signature.json`, requires
  the leaf CN to equal the reserved identity `core`, and applies the core file-set
  rules (spec §3.6) — extra exclusions (`core/signature.json`,
  `core/js/mimetypelist.js`, the top-level `data`/`themes`/`config`/`apps`/
  `assets`/`lost+found` directories) and the root `.htaccess` baseline
  normalization (hash only the bytes above the
  `#### DO NOT CHANGE ANYTHING ABOVE THIS LINE ####` marker), transcribed verbatim
  from the legacy PHP `Checker` so the manifest matches the verifier.
- `--attest` (Mode-2 attestation) is **not yet implemented**. It depends on the
  not-yet-finalized `bind(H, T)` token byte layout and the attestation-workflow
  result-delivery mechanism. It exits with a clear "not yet implemented" error.

## Usage

```
ocsign [flags]

Required:
  --path string     Path to the root directory to sign. For an app, the directory
                    whose appinfo/info.xml declares the app id; for core, the
                    server root.
  --key  string     Path to the signer's PEM private key (EC P-384, or RSA-4096
                    / RSA-2048 fallback). Never transmitted; used locally only.
  --cert string     Path to the issued leaf certificate (PEM). For --core the leaf
                    CN must be "core"; otherwise it must equal the app id.

Optional:
  --chain string    Path to a PEM file with the intermediate cert(s) to embed as
                    certificates.chain[]. If omitted, chain[] is left empty.
  --core            Sign the core server root: write core/signature.json and apply
                    the core file-set rules (spec §3.6).
  --allow-vcs       Sign even when --path holds a .git entry. Off by default; see
                    "Repository checkouts are refused" below.
  --out  string     Override output path (default: <path>/appinfo/signature.json,
                    or <path>/core/signature.json with --core).
  --dry-run         Compute and print the manifest + would-be signature.json to
                    stdout; write nothing.

Exit codes:
  0  success
  1  usage / input error (missing flag, unreadable key/cert/path, --path is a
     repository checkout)
  2  signing error (key/cert mismatch, unsupported key type)
  3  attestation error (--attest requested but workflow failed)
```

### Example

```sh
ocsign --path ./example-app \
       --key  developer.key \
       --cert leaf.crt \
       --chain intermediate.crt
```

### Repository checkouts are refused

`--path` must point at the **app payload** — the staging directory a release
tarball is built from, e.g. `build/artifacts/appstore/<app>` — not at the
repository working tree. In app mode the manifest hashes *everything* under
`--path` bar `appinfo/signature.json` and OS cruft, so signing a checkout
produces a signature that legitimizes `.git` internals, tests and CI config as
part of the app.

Nothing downstream can tell such a signature apart from a correct one: it
verifies, because the manifest genuinely describes the tree that was signed.
`ocsign` therefore refuses when `--path` contains a `.git` entry at any depth —
a directory from an ordinary clone, or a regular file from a worktree or
submodule gitlink — and exits 1 before reading any key material.

The marker is the evidence, not the harm, so its own contents are irrelevant — an
empty `.git` is refused too. `rsync -a --exclude='.git/*'` leaves exactly that
shape: an empty marker over a working tree whose tests and CI config the manifest
still hashes whole.

Only the file set the manifest covers is searched. With `--core` that excludes the
top-level `data/`, `apps/`, `themes/`, `config/`, `assets/` and `lost+found/`
(spec §3.6), so a `.git` there — an app installed with `git clone`, or a user's
repository synced into their files — is not a refusal. A symlinked `--path` is
resolved first, so the check always sees the real tree.

Pass `--allow-vcs` to sign anyway; the use for it is signing a development
checkout in place to exercise verification locally. A release pipeline should
package the payload first and point `--path` at that instead.

## Building

```sh
go build ./cmd/ocsign
```

`ocsign` uses only the Go standard library for cryptography and supports
`GOOS`/`GOARCH` cross-compilation for linux/darwin/windows on amd64/arm64.

`ocsign --version` prints the build version.

## Releases

Pushing a `v*` tag runs the release workflow, which cross-compiles all six
OS/arch targets, produces checksummed archives (`SHA256SUMS`), and publishes a
GitHub Release. To reproduce the artifacts locally:

```sh
scripts/build-release.sh v0.2.0 dist
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
