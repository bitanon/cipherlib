---
name: release
description: Run the cipherlib release ritual — local pre-flight mirroring release-test.yml, CHANGELOG entry, single version-bump commit, matching vX.Y.Z tag, tag push, and CI watch through pub.dev publish. Use ONLY when the maintainer explicitly asks to release, publish, or bump the version.
---

# Release cipherlib

Publishing is fully automated: pushing a `vX.Y.Z` tag triggers
`.github/workflows/release.yml`, which verifies tag == pubspec version, runs
the heavy test matrix (`release-test.yml`), publishes to pub.dev via OIDC, and
creates a GitHub Release from the top CHANGELOG section. Your job is to
prepare the repo so that pipeline cannot fail, then push the tag.
**Never run `dart pub publish` yourself.**

## Step 0 — Preconditions (abort if any fails)

- The maintainer explicitly requested a release this session.
- `git status` clean; on `main`; `git pull` up to date with origin.
- Decide the version with the maintainer if not stated: pre-1.0 semver as
  practiced here — breaking/API changes bump minor (0.3.0 → 0.4.0), fixes
  bump patch.

## Step 1 — Dependency-chain check (bottom-up)

cipherlib depends on hosted `hashlib`, which depends on hosted
`convertlib` (never path deps). Before releasing cipherlib:

1. Check `../hashlib` and `../convertlib` for commits after their latest
   tag (`git -C ../hashlib log $(git -C ../hashlib describe --tags --abbrev=0)..HEAD --oneline`).
2. If cipherlib's changes need an unreleased hashlib change, the chain must
   ship first: convertlib → hashlib (bumping its `convertlib:`
   constraint) → cipherlib (bumping its `hashlib:` constraint). Each sibling
   follows its own version of this same ritual; confirm with the maintainer
   before touching sibling repos (AGENTS.md §6, Stop-2 applies to code, but
   releases are maintainer-decision territory too).
3. If no cross-repo dependency is needed, leave the `hashlib:` constraint
   alone unless the maintainer asks to raise it.

## Step 2 — Local pre-flight (mirror of release-test.yml, cheap-first)

Run in order; stop at the first failure and report instead of releasing:

```sh
dart pub get
dart format --output=none --set-exit-if-changed .
dart analyze --fatal-infos
dart test -p vm
dart test -p node                      # release matrix includes node
cd test_integration && dart pub get && dart run main.dart && cd ..
dart pub global activate pana >/dev/null && dart pub global run pana --exit-code-threshold 0
```

pana must be a perfect score (`--exit-code-threshold 0`) — the release
pipeline enforces it. Common pana failures: README/dartdoc issues, missing
example, analysis warnings.

Also run `dart pub publish --dry-run` locally — it catches `.pubignore` and
metadata problems before CI does.

## Step 3 — CHANGELOG

Ensure `CHANGELOG.md` has a top section covering everything since the last
tag (`git log $(git describe --tags --abbrev=0)..HEAD --oneline` to check):

```markdown
# X.Y.Z

- 🌊 <feature-level summary bullet>
- 🛠️ <internals/maintenance bullet>
- ✅ <test/coverage bullet>
```

House style: **H1** heading `# X.Y.Z` (not `##`), newest first, short
emoji-prefixed bullets summarizing themes — not one bullet per commit.
Look at the previous two entries and match their voice.

## Step 4 — Bump commit

One commit touching **only** `CHANGELOG.md` and `pubspec.yaml`:

1. Set `version: X.Y.Z` in `pubspec.yaml`.
2. Commit message: `Release version X.Y.Z with <one-line summary>`
   (e.g. `Release version 0.4.0 with restored and redesigned stream support`).
3. Push to `main` and wait for the regular Test workflow to go green before
   tagging (`gh run watch` or check `gh run list --limit 1`).

## Step 5 — Tag and watch

```sh
git tag vX.Y.Z          # MUST exactly match pubspec version — CI hard-fails otherwise
git push origin vX.Y.Z
gh run list --workflow=release.yml --limit 1   # then gh run watch <id>
```

Watch all four jobs: version check → release tests (wide matrix: 3 OSes,
stable+beta+2.19 SDKs, vm+node) → publish → changelog/GitHub-Release. If the
matrix fails on something environment-specific, report; do not force-retag.
A failed publish after a successful tag needs maintainer guidance (deleting
and re-pushing tags re-triggers the pipeline; pub.dev versions are immutable).

## Step 6 — Post-release verification

- `https://pub.dev/packages/cipherlib` shows X.Y.Z (may take a few minutes).
- GitHub Release `vX.Y.Z` exists with the CHANGELOG section as its body.
- Report: version published, CI run link, and (if part of a chain) which
  sibling releases preceded it.
