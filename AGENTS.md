# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Overview

`cipherlib` is a pure-Dart cryptography package implementing symmetric ciphers
(AES with multiple modes, ChaCha20, XChaCha20, Salsa20, XSalsa20, XOR) and
their AEAD variants with Poly1305. Its only runtime dependency is
[`hashlib`](https://pub.dev/packages/hashlib).

Because this is a cryptographic library, **correctness and constant-time
behavior matter more than cleverness**. Never "optimize" an algorithm without
reference test vectors to back the change.

## Repository Layout

```
lib/
  cipherlib.dart            # Main barrel export
  codecs.dart               # Re-exports hashlib codecs (hex, utf8, etc.)
  hashlib.dart              # Re-exports hashlib primitives used here
  random.dart               # Re-exports hashlib random utilities
  src/
    core/                   # Abstract cipher/AES base classes
    algorithms/             # Concrete algorithm implementations
      aes_modes/            # One file per AES mode (cbc, ctr, gcm, xts, ...)
      padding.dart          # Padding schemes
      chacha20.dart, salsa20.dart, aead_cipher.dart, xor.dart
    utils/                  # Internal helpers (nonce, chunk stream, typed_data)
    aes.dart, chacha20.dart, ...   # Per-family barrel files
test/                       # One `*_test.dart` per algorithm / mode
  fixtures/                 # Known-answer test vectors
test_integration/           # Cross-library parity tests (pointycastle, cryptography)
benchmark/                  # Micro-benchmarks driving BENCHMARK.md
example/                    # Public usage example (kept in sync with README)
scripts/                    # sh + bat helpers (benchmark, coverage, compiled)
```

## Common Commands

Run everything from the repo root.

| Task                          | Command                                 |
| ----------------------------- | --------------------------------------- |
| Install deps                  | `dart pub get`                          |
| Static analysis               | `dart analyze`                          |
| Format check (must pass)      | `dart format --set-exit-if-changed .`   |
| Run all tests (VM, default)   | `dart test -p vm`                       |
| Run a single test file        | `dart test -p vm test/aes_cbc_test.dart` |
| Run tests matching a name     | `dart test -p vm -N "pattern"`          |
| Run on all platforms (rare)   | `dart test`                             |
| Coverage (LCOV + Cobertura)   | `sh scripts/coverage.sh`                |
| Benchmarks (regenerates md)   | `sh scripts/benchmark.sh`               |
| Run the example               | `dart run example/cipherlib_example.dart` |

**Run tests and coverage on the VM by default** (`dart test -p vm`, which is
also what `scripts/coverage.sh` uses). `dart_test.yaml` declares `vm` and
`node` platforms, but only invoke `node` (or `dart test` without `-p`) when
the change specifically targets web/JS compatibility or a bug reported there.
Tag tests that use `dart:io` or other non-web APIs with `@Tags(['vm-only'])`.

## Coding Conventions

- **Dart SDK**: `>=2.19.0 <4.0.0`. Do not use language features newer than
  Dart 2.19 (no records, patterns, class modifiers, `switch` expressions,
  etc.) unless you also bump the SDK constraint in `pubspec.yaml`.
- **Lints**: follow `analysis_options.yaml` (extends `package:lints/recommended`
  plus extras like `only_throw_errors`, `always_declare_return_types`,
  `comment_references`). Run `dart analyze` before finishing any change.
- **Formatting**: always `dart format .` before committing.
- **License header**: every `lib/src/**/*.dart` file starts with
  `// Copyright (c) 2024, Sudipto Chandra` and `// All rights reserved. Check
  LICENSE file for details.`. Preserve it on edits and add it to new files.
- **Public API**: lives under `lib/*.dart` barrels. New algorithms should be
  exported through the matching family barrel in `lib/src/<family>.dart` and
  then re-exported from `lib/cipherlib.dart`.
- **Errors**: throw typed `Error`/`Exception` subclasses; never `throw "str"`.
- **Streaming vs one-shot**: most ciphers expose both a class (e.g. `ChaCha20`)
  and top-level helpers (`chacha20`, `chacha20Stream`). Keep both in sync when
  adding features.
- **Typed data**: prefer `Uint8List` over `List<int>` on hot paths; reuse
  helpers in `lib/src/utils/typed_data.dart`.

## Testing Rules

- Every new algorithm, mode, or public function needs a `test/*_test.dart`
  file with at least one known-answer test sourced from the relevant RFC /
  spec / libsodium / NIST vector. Put the raw vectors under `test/fixtures/`.
- Mirror the existing structure: a `validation` group for argument checks and
  additional groups for KATs and round-trip tests.
- When touching an existing algorithm, run the full VM suite
  (`dart test -p vm`) — many cross-cutting tests (`cipher_test.dart`,
  `compare_test.dart`, `nonce_test.dart`, `padding_test.dart`) exercise
  shared code paths. Only add a `node`/multi-platform run when the change
  could affect JS/web behavior.
- `test_integration/` compares our output against `pointycastle` and
  `cryptography`. Do not remove coverage there; add new comparisons when
  introducing algorithms those libraries support.

## Security & Correctness Guardrails

- Do not introduce new runtime dependencies beyond `hashlib` without a strong
  reason. Do not vendor reference implementations without attribution.
- Never log, print, or expose keys, nonces, or intermediate state in library
  code. Debug output belongs in tests only.
- Treat MAC verification (`Poly1305`, `GCM`) as constant-time — do not short
  circuit on the first mismatched byte.
- When changing performance-sensitive code, re-run `sh scripts/benchmark.sh`
  and update `BENCHMARK.md` in the same change.

## Docs & Release Hygiene

- Update `CHANGELOG.md` for any user-visible change; follow the existing
  "## X.Y.Z" + bullet list style.
- Keep `README.md`, `example/cipherlib_example.dart`, and `BENCHMARK.md` in
  sync — the README embeds the example and benchmark tables verbatim between
  `<!-- file: ... -->` markers.
- Bump `version:` in `pubspec.yaml` only when the maintainer asks for a
  release.

## What Not To Do

- Do not edit files under `build/`, `coverage/`, or `.dart_tool/`; they are
  generated.
- Do not weaken lints or add `// ignore:` comments to silence analyzer
  warnings — fix the underlying issue.
- Do not commit benchmark output from machines other than the documented
  reference (Apple M3 Pro) unless explicitly asked; local numbers can mislead.
