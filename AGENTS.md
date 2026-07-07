# AGENTS.md — cipherlib operating manual

Operating manual for AI coding agents working in this repository. Every rule
here is checkable; when a rule and the code disagree, trust the code and
report the conflict (§6, Flag-1).

## 0. Prime directive

`cipherlib` is a pure-Dart cryptography package providing symmetric ciphers
and post-quantum key encapsulation (ML-KEM). In this repo,
**correctness is proven by known-answer test vectors (KATs), not by reasoning
and not by round-trip tests**. A stream cipher whose keystream is completely
wrong still round-trips perfectly (encrypt and decrypt apply the same XOR), so
"my change encrypts and decrypts fine" is evidence of nothing. If you change
anything that touches keystream generation, counters, state layout, tags, or
padding, a spec-sourced KAT must cover the changed path *before* you conclude
the change is correct. No covering KAT → stop and escalate (§6).

Second directive: **do not be clever**. This codebase intentionally contains
duplicated helpers, hand-unrolled loops, seemingly redundant copies, and
asymmetries between similar algorithms. Almost all of them are load-bearing.
§4 names the ones you will be tempted to "fix".

## 1. Orientation

**What**: symmetric ciphers (AES in 9 modes, ChaCha20, XChaCha20, Salsa20,
XSalsa20, XOR) plus AEAD variants with Poly1305, and the ML-KEM post-quantum
key encapsulation mechanism (FIPS 203). Published to pub.dev as
`cipherlib` (repo: `bitanon/cipherlib`, default branch `main`).

**Dependency chain** (all hosted on pub.dev — never path deps, never
`pubspec_overrides.yaml`):

```text
hashlib_codecs  ──►  hashlib  ──►  cipherlib
(codecs, ByteCollector)  (Poly1305, HashDigest, random)  (this repo)
```

Sibling repos live at `../hashlib` and `../hashlib_codecs`. cipherlib's only
runtime dependency is `hashlib`. Things cipherlib gets from hashlib and must
NOT reimplement: `Poly1305`, `HashDigest` (`.bytes`, `.hex()`, `.isEqual`),
`MACHashBase`, `HashDigestSink`, `randomBytes`/`randomNumbers`/`fillRandom`,
`ByteCollector`, hex/utf8 codecs. A bug in any of those is a **cross-repo
issue** — report it, do not patch around it here (§6, Stop-2).

**Layout**:

```text
lib/
  cipherlib.dart              # public entrypoint → exports src/cipherlib_base.dart
  codecs.dart | hashlib.dart | random.dart   # pure re-exports of hashlib libraries
  src/
    cipherlib_base.dart       # aggregator: exports every family barrel below
    <family>.dart             # family barrel: `export ... show X` + top-level fn
    core/cipher.dart          # CipherBase, Cipher, StreamCipher, CipherPair, SaltedCipher
    core/aes.dart             # AESCore: S-boxes, T-tables (GENERATED, see §4.F4), key expansion
    algorithms/               # concrete implementations (chacha20.dart, salsa20.dart, ...)
      aes_modes/              # one file per AES mode (cbc, ctr, gcm, ige, xts, ...)
      aead_cipher.dart        # AEADCipher / AEADStreamCipher / AEADResult(+WithIV)
      padding.dart            # Padding.none/zero/byte/ansi/pkcs7/pkcs5
    utils/                    # nonce.dart (Nonce/Nonce64/Nonce128), typed_data.dart, chunk_stream.dart
test/                         # one *_test.dart per algorithm + cross-cutting tests
  fixtures/                   # bulk KAT vectors as Dart data files
test_integration/             # SEPARATE pub package; parity vs pointycastle & cryptography
benchmark/                    # hand-rolled harness (_base.dart) → generates BENCHMARK.md
example/                      # 10 runnable examples; cipherlib_example.dart is embedded in README
scripts/                      # paired .sh/.bat: benchmark, coverage, compiled, globals
tool/aes_cache_gen.dart       # generator for the AES T-tables in core/aes.dart
```

Generated / never hand-edit: `build/`, `coverage/`, `doc/`, `.dart_tool/`,
the T-table block in `core/aes.dart`, and `BENCHMARK.md` (regenerate it).

**Public API surface** = what `lib/cipherlib.dart` reaches. New symbols become
public in three steps: `algorithms/<x>.dart` → family barrel
`src/<x>.dart` (`export 'algorithms/<x>.dart' show X;`) → add the barrel to
`src/cipherlib_base.dart`. Keep every `show` list and export list
alphabetical (`combinators_ordering` lint).

## 2. Commands

Run from the repo root.

| Task | Command |
| --- | --- |
| Install deps | `dart pub get` |
| Static analysis (CI parity) | `dart analyze --fatal-infos` |
| Format check (must pass) | `dart format --set-exit-if-changed .` |
| All tests (default) | `dart test -p vm` |
| One test file | `dart test -p vm test/chacha20_test.dart` |
| Tests matching a name | `dart test -p vm -N "pattern"` |
| Web/JS tests (only when needed) | `dart test -p node` |
| Integration parity suite | `cd test_integration && dart pub get && dart run main.dart` |
| Coverage (LCOV+Cobertura+JUnit) | `sh scripts/coverage.sh` |
| Benchmarks (regenerates md) | `sh scripts/benchmark.sh` (M3 Pro only, §4.F5) |
| One compiled benchmark | `sh scripts/compiled.sh benchmark/<file>.dart` |
| Run the main example | `dart run example/cipherlib_example.dart` |
| Regenerate AES T-tables | `dart run tool/aes_cache_gen.dart` (prints to stdout) |
| Package score (release only) | `dart pub global run pana --exit-code-threshold 0` |

Notes:

- `dart test` **without** `-p vm` runs the `node` platform too (slow, needs
  Node.js). Default to `-p vm`; add `node` only for web-relevant changes.
- `dart analyze` alone is NOT CI parity — CI uses `--fatal-infos`, so info-level
  findings fail the build.
- Tests needing `dart:io` or other non-web APIs: tag with `@Tags(['vm-only'])`
  (wired in `dart_test.yaml` to skip everywhere except VM).
- `test_integration/` is its own pub package with its own `pubspec.yaml`; it
  uses plain `assert`-style helpers (`test_integration/src/assertions.dart`),
  not `package:test`.

## 3. Conventions

### 3.1 Language constraints (CI-enforced)

- SDK floor is **Dart 2.19** and CI tests it on Linux/macOS/Windows. Forbidden
  unless the maintainer bumps `pubspec.yaml`: records, patterns, `switch`
  expressions, class modifiers (`sealed`, `final class`, ...), unnamed
  libraries with new syntax — anything post-2.19.
- Lints: `package:lints/recommended` plus the extras in
  `analysis_options.yaml`. Two with visible consequences:
  `comment_references` (every `[Symbol]` in a dartdoc must resolve) and
  `combinators_ordering` (alphabetical `show`/`hide` lists).
- Never add `// ignore:` or weaken a lint to silence the analyzer — fix the
  cause.
- No new runtime dependencies. `hashlib` is the only one, deliberately.

### 3.2 File anatomy

Every `lib/src/**/*.dart` file starts with:

```dart
// Copyright (c) <year>, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.
```

Preserve the existing year on edits; use the current year for new files.

A typical algorithm file, top to bottom: license header → imports →
`const int _mask32 = 0xFFFFFFFF;` and private helpers (`_rotl32` is
duplicated per file on purpose — do not extract a shared one) → the class.

### 3.3 Class architecture — pick the right base

Defined in `lib/src/core/cipher.dart`:

| Situation | Extend/mix | Example |
| --- | --- | --- |
| Same transform both directions (keystream XOR) | `StreamCipher` (+ `SaltedCipher` if IV) | `ChaCha20`, `Salsa20`, `XOR`, AES-CTR/CFB/OFB |
| Encrypt ≠ decrypt | `CipherPair`/`StreamCipherPair` with separate `...Encrypt`/`...Decrypt` ciphers | AES-CBC/ECB/GCM/IGE/PCBC/XTS |
| Authenticated | `AEADStreamCipher<Cipher, Poly1305>` (algorithms/aead_cipher.dart) | `ChaCha20Poly1305` |

House idioms (copy them, don't improvise):

- Private `const X._(this.key, this.iv, ...)` constructor + public
  `factory X(...)` that validates and normalizes (`validateLength(...)`,
  `toUint8List(...)` from `utils/typed_data.dart`) and throws
  `ArgumentError.value(value, 'name', 'length must be ...')`.
- Public API accepts `List<int>`; convert to `Uint8List` exactly once at the
  factory boundary. Hot paths use `Uint32List` state aliased via
  `Uint8List.view(state32.buffer)`.
- Visibility tiers: `_name` = file-private. `$name` = "blessed internal" —
  public for cross-file access inside the package but not for users (e.g.
  `$otk()`, `$mac()`, `AESCore.$encrypt`). Do not promote `$`-members into
  documented API and do not rename them.
- Small hot functions carry **both** pragmas:
  `@pragma('vm:prefer-inline')` and `@pragma('dart2js:tryInline')`.
- Block functions are hand-unrolled with 16 locals (`s0..s15`) and C-style
  loops with pre-declared `int i, j, n;`. Match this style in hot code; do not
  refactor unrolled rounds into loops "for readability".
- AES mode naming: `AESIn<MODE>Mode` (the pair), `AESIn<MODE>ModeEncrypt` /
  `...Decrypt` (the sides), `...CipherCore` (bare engine). AEAD naming:
  `<Cipher>Poly1305`, attached via
  `extension <Cipher>ExtensionForPoly1305 on <Cipher>`.
- Top-level one-shot functions are lowercase-run-together: `chacha20`,
  `xchacha20poly1305`. AES has none — its API is the builder
  `AES(key).cbc(iv)`, `AES(key).gcm(iv)`, etc.
- `name` getters follow the spec-string format: `"ChaCha20"`,
  `"AES/CBC/${padding.name}"`, `"XSalsa20/Poly1305"`.

### 3.4 Documentation style

- Class dartdoc states the spec basis with a footnote-style link so
  `comment_references` stays satisfied:

  ```dart
  /// This implementation is based on the [RFC-8439][rfc]
  ///
  /// [rfc]: https://www.rfc-editor.org/rfc/rfc8439.html
  ```

- Constructor/factory docs use a `/// Parameters:` block with
  `/// - [name] : description.` lines, stating exact accepted sizes and
  defaults (`(Default: random)`).
- AES mode factories include ASCII data-flow diagrams — imitate for new modes.
- README "Features" table has a **Source** column (`RFC-8439`,
  `NIST.FIPS.197`, `libsodium`, `Snuffle-2005`, ...). Every new algorithm adds
  a row, and every symbol named in that table must actually exist in `lib/`
  (grep before writing; see §4.A1 for how it once went wrong).

### 3.5 Error conventions (tests assert exact types)

| Condition | Throw |
| --- | --- |
| Bad key/nonce/counter length or combination | `ArgumentError` (stream ciphers, factories) |
| Invalid state/config in AES modes | `StateError` |
| AEAD/GCM authentication failure | `StateError('Message authenticity check failed')` / GCM: `'Message authentication check failed'` |
| Unsupported operation (`StreamCipher.cast`) | `UnsupportedError` |
| Never | `throw 'string'` (`only_throw_errors` lint) |

Do not change an existing error type or message — tests match them.

### 3.6 Git & release conventions

- **Never commit or push unless the maintainer's IMMEDIATE message explicitly
  asks for it.** "Fix X" means edit the working tree and stop; an earlier
  "commit it" in the conversation does not carry forward to later changes.
  When not asked, finish with the working tree dirty and report what changed.
- Work directly on `main` in small linear commits (PRs are for external
  contributors and automated fixes). Messages: imperative, capitalized first
  word, no trailing period, no `feat:`-style prefixes. Examples from history:
  `Refactor AES mode ciphers to extend StreamCipher for streaming support`,
  `Fix formatting`.
- `CHANGELOG.md` entries use **H1** headings — `# X.Y.Z` — newest first, with
  short emoji-prefixed bullets (🌊 🔐 🛠️ ✅ style). Update it for every
  user-visible change.
- The version bump is its **own commit** touching only `CHANGELOG.md` +
  `pubspec.yaml`, titled `Release version X.Y.Z with <one-line summary>`.
- Tag `vX.Y.Z` must exactly match `pubspec.yaml` — `release.yml` hard-fails
  otherwise. Pushing the tag triggers the release pipeline (wider test matrix,
  pana with `--exit-code-threshold 0`, OIDC publish, GitHub Release from
  the top CHANGELOG section). **Never run `dart pub publish` by hand and never
  bump `version:` unless the maintainer asks for a release.**
- Three artifacts must stay in sync: `example/cipherlib_example.dart`,
  `BENCHMARK.md`, and the copies of both embedded in `README.md` between
  paired `<!-- file: <path> -->` markers. Touch one → update the embed.

## 4. Mistakes you will make here (named, with the rule that prevents each)

### A. API illusions — the docs lie in places; the code doesn't

- **A1. Phantom `*Stream` functions.** There are no top-level `chacha20Stream`
  / `xorStream`-style helpers — the README once advertised them without them
  existing. Streaming is `ChaCha20(key, nonce).bind(stream)` (a
  `StreamTransformer`) or the byte-level `StreamCipherExtension.stream()`.
  Rule: never call or document a symbol without grepping it in `lib/` first.
- **A2. There is no `.tag`.** AEAD results expose `mac` (a hashlib
  `HashDigest`): `result.mac.bytes`, `result.mac.hex()`.
- **A3. AEAD one-shot functions verify via parameter, not a method.**
  `xchacha20poly1305(data, key, nonce: iv, mac: tag)` throws
  `StateError` on mismatch; they always return `AEADResultWithIV`
  (data + mac + iv) for both directions.
- **A4. `cast()` on any `StreamCipher` throws `UnsupportedError`** — by
  design, with a test asserting it. Don't implement it.

### B. Keystream & layout traps — wrong output that still round-trips

- **B1. ChaCha and Salsa are NOT layout-twins.** ChaCha20: counter occupies
  IV words 0–1 (counter first, then nonce), increment is 32- or 64-bit
  depending on `counterBytes`, default counter **1**. Salsa20: nonce occupies
  words 0–1, counter words 2–3, always 64-bit carry, default counter **0**.
  Rule: never copy counter/layout code between the two families; validate any
  touch with that family's KATs.
- **B2. HChaCha20 ≠ HSalsa20 subkey extraction.** HChaCha20 takes state words
  `[0..3, 12..15]`; HSalsa20 takes `[0, 5, 10, 15, 6, 7, 8, 9]`. The
  sigma/tau constants also differ between 16- and 32-byte keys. Transposing
  either produces a plausible-looking wrong subkey.
- **B3. Round-trip tests cannot catch keystream bugs** (§0). Any PR whose only
  new evidence is "encrypt→decrypt returns the input" has proven nothing about
  correctness. Rule: KAT or it didn't happen.
- **B4. AES endianness is per-mode.** `AESCore.$encrypt`/`$decrypt` are
  big-endian; `$encryptLE`/`$decryptLE` swap in and out. CTR uses `$encrypt`
  then swaps output; CBC/GCM/XTS use the LE variants; GCM additionally stores
  GHASH state pre-swapped. Rule: when touching a mode, keep its existing
  variant; never "standardize" on one.
- **B5. GCM internals are a high-risk zone.** The counter increments only the
  last 32 bits big-endian; the length block packs **bit** lengths (`<< 3`);
  streaming decrypt holds back a `tagSize` ring buffer to split ciphertext
  from trailing tag. Rule: do not restructure `gcm.dart` without NIST KATs
  green before and after.
- **B6. XTS steals ciphertext.** The final partial block swaps bytes with the
  previous block, and decrypt pre-multiplies alpha for the second-to-last
  block only when the last is partial; messages must be ≥ 16 bytes. Rule:
  any xts.dart change requires partial-block-length tests (17, 31 bytes...).
- **B7. Validation rules are intentionally non-uniform.** ChaCha nonce ∈
  {8,12,16}, XChaCha ∈ {24,28,32}, Salsa ∈ {8,16}, XSalsa ∈ {24,32}; a
  16/32-byte nonce forbids an explicit counter; the size of a defaulted random
  nonce depends on whether a counter was given. Rule: don't unify, don't
  "fix inconsistencies" — each mirrors its spec.

### C. Buffer & aliasing traps — silent catastrophic failure

- **C1. `toUint8List` aliases instead of copying** when the input is already a
  full-view `Uint8List`. Where a copy matters, the code says `.sublist(0)`
  explicitly (e.g. XSalsa20 copies key and nonce). Rule: never delete a
  "redundant" `.sublist(0)`; never mutate a buffer you received through
  `convert()`/factory parameters unless the surrounding code proves ownership.
  There is a regression test: `'constructor should not mutate caller key buffer'`.
- **C2. `resetIV()` must re-derive dependent state.** The `SaltedCipher` mixin
  only randomizes the IV bytes in place. X-variants override it to re-run
  HChaCha/HSalsa; AEAD classes additionally rekey Poly1305 from the fresh
  one-time key. Rule: any cipher with derived keys/subnonces MUST override
  `resetIV()` and re-derive, and needs a `'reset iv'` test asserting subkey,
  subnonce, keypair, and tag all change while `key` doesn't. Forgetting this
  = keystream reuse, the worst failure a stream cipher can have.
- **C3. `bind()` must yield independent chunks** — `yield result.sublist(0)`,
  never the reused internal buffer. Tested by `'bind emits independent full
  chunks'`.

### D. Constant-time & secrecy traps

- **D1. The GCM tag comparison loops over ALL bytes without breaking.** It
  looks like an obvious "add an early return" cleanup. It is deliberate, and
  `CountingTagReadList` in `test/aes_gcm_test.dart` asserts all 16 tag bytes
  are read on a tampered tag. Rule: never short-circuit a MAC comparison.
- **D2. `HashDigest.isEqual` IS constant-time for content, but not for
  length.** hashlib_codecs' `ByteCollector.isEqual` (since 3.3.x) accumulates
  a running diff over all bytes and exits early only on a length mismatch, so
  the Poly1305 AEAD verify path and KEM shared-secret comparisons may rely on
  it. The ML-KEM decapsulation path still uses its own fixed-length
  `$verify`/`_cmov` mask routines (the re-encrypted ciphertext comparison and
  key selection must be branch-free). Rule: never short-circuit a MAC or
  secret comparison on content, and verify the shipped hashlib_codecs
  behavior before relying on it after a dependency bump.
- **D3. Never log, print, or embed in exception messages** any key, nonce,
  keystream, or intermediate state in `lib/` code. Debug output belongs in
  tests only.

### E. Sign/verify semantics traps

- **E1. `sign` MACs the cipher OUTPUT; `verify` MACs the INPUT.** Consequence:
  in a round-trip, the encrypt result's mac (over ciphertext) ≠ the decrypt
  result's mac (over recovered plaintext). Tests assert this with
  `isNot(equals(...))` — it looks like a bug; it is intended. Rule: do not
  "fix" those assertions, and do not feed a decrypt-side mac back as the
  verification tag for ciphertext.
- **E2. The Poly1305 length-block builder's argument names are inverted
  relative to the packing** — the first (`high`) argument of `_build128` is
  emitted as the LOW 8 bytes. Every AEAD tag depends on this. Rule: treat
  `$mac`/`_build128` in `aead_cipher.dart` as frozen unless armed with RFC-8439
  §2.8.2 vectors.
- **E3. Poly1305 sink feeding order is fixed by spec**: AAD, zero-pad to 16,
  ciphertext, zero-pad to 16, then 16-byte LE `len(aad) ‖ len(ciphertext)`
  block, then `close()`. The pad predicate is `(len & 15) != 0`. Don't
  reorder, don't pad unconditionally.

### F. Process & tooling traps

- **F1. Post-2.19 Dart syntax compiles locally, then fails CI** (the matrix
  pins SDK 2.19). Rule: if unsure whether a feature is 2.19-safe, don't use it.
- **F2. `dart analyze` passing ≠ CI passing.** Use `--fatal-infos`.
- **F3. Plain `dart test` runs the node platform** — slow and environment-
  dependent. Use `-p vm` unless testing web behavior.
- **F4. The AES T-tables are generated.** Never hand-edit the constant blocks
  under the `Output from 'dart run tool/aes_cache_gen.dart'` marker in
  `core/aes.dart`; change the generator, re-run it, paste its stdout.
- **F5. Benchmark numbers are machine-locked.** `BENCHMARK.md` only carries
  numbers from the reference 36GB Apple M3 Pro (the footer says so). On any
  other machine: run for relative comparison, never commit. And BENCHMARK.md
  is embedded in README (§3.6) — regenerating one without re-embedding the
  other desyncs them.
- **F6. `test_integration/` won't run via `dart test`.** It's a separate
  package: `cd test_integration && dart pub get && dart run main.dart`.
- **F7. Cross-cutting tests exercise shared paths** (`cipher_test.dart`,
  `compare_test.dart`, `correctness_test.dart`, `nonce_test.dart`,
  `padding_test.dart`). A "local" change to one algorithm can break them —
  always finish with the full VM suite, not just the algorithm's own file.

## 5. Quality bar per deliverable (checkable)

### Every change, no exceptions

- [ ] `dart format --set-exit-if-changed .` exits 0
- [ ] `dart analyze --fatal-infos` exits 0
- [ ] `dart test -p vm` fully green (not just the touched file)
- [ ] No new dependencies in `pubspec.yaml`; no `// ignore:` added; no lint
      weakened
- [ ] License header present and year preserved on every touched
      `lib/src/**` file
- [ ] No Dart >2.19 syntax introduced
- [ ] `CHANGELOG.md` bullet added if the change is user-visible

### New algorithm / mode / AEAD variant

All of the above, plus:

- [ ] Implementation in `lib/src/algorithms/` (or `aes_modes/`) with spec
      citation footnote in the class dartdoc
- [ ] Correct base class per §3.3; factory validates all input sizes with
      `validateLength`
- [ ] Family barrel `lib/src/<x>.dart` with `export ... show` (alphabetical)
      + top-level one-shot function; wired into `src/cipherlib_base.dart`
- [ ] Test file `test/<x>_test.dart` with the canonical groups, in order:
      `validation` (name, empty message, key-size sweep 0..99, nonce-size
      sweep, counter-rejection, random-nonce-if-null), `known inputs`
      (KATs), `correctness` (round-trips over sizes 0..99 with
      `reason: '[size: $j]'`), `stream support` (bind-vs-convert over uneven
      chunks, independent chunk buffers, `cast` throws)
- [ ] ≥ 1 KAT from RFC/NIST/libsodium/reference implementation, with the
      source URL (and section) as a comment; bulk vectors go in
      `test/fixtures/<x>_vectors.dart`
- [ ] If it has a counter: `counter increment` tests crossing the 32-bit and
      64-bit boundaries
- [ ] If salted/derived-key: `'reset iv'` test (§4.C2) and
      no-caller-buffer-mutation test (§4.C1)
- [ ] If pointycastle or cryptography implements it: parity comparison added
      to `test/compare_test.dart` and/or `test_integration/src/`
- [ ] Benchmark file in `benchmark/` following `chacha20.dart`'s pattern,
      registered in `benchmark/benchmark.dart`
- [ ] README Features-table row with Source column; example file if the API
      shape is new; CHANGELOG bullet

### Bug fix

- [ ] A regression test that fails before the fix and passes after (put it in
      the algorithm's test file, matching group conventions)
- [ ] Error-type/message assertions unchanged unless the bug IS the error type
- [ ] Full VM suite green (cross-cutting tests, §4.F7)

### Performance change

- [ ] All KATs green before AND after (run twice; keystream code is guilty
      until proven innocent)
- [ ] One-shot and stream outputs still byte-identical (covered by
      `stream support` groups — run them)
- [ ] Benchmark delta measured and reported in the summary
      (`sh scripts/compiled.sh benchmark/<algo>.dart` for one algorithm)
- [ ] `BENCHMARK.md` regenerated ONLY if on the reference M3 Pro, with README
      re-embedded in the same change

### Docs change

- [ ] Every code symbol mentioned actually exists (grep `lib/`) — §4.A1 is
      what happens otherwise
- [ ] README `<!-- file: ... -->` embeds still byte-match their source files
- [ ] `dart analyze --fatal-infos` still clean (dartdoc references are checked)

### Release (only when explicitly requested)

- [ ] Working tree clean, on `main`, synced with origin
- [ ] Local pre-flight: format + analyze + `dart test -p vm` +
      `dart test -p node` + integration suite + pana score clean
- [ ] CHANGELOG has a `# X.Y.Z` section covering everything since the last tag
- [ ] Single bump commit `Release version X.Y.Z with <summary>` touching only
      CHANGELOG.md + pubspec.yaml
- [ ] Tag `vX.Y.Z` == pubspec version, pushed after the commit; CI watched
      through publish

## 6. When uncertain — escalation rules

**STOP and ask the maintainer** (do not proceed, do not pick a default) when:

- **Stop-1: No covering KAT.** You are changing keystream/counter/tag/padding
  logic and no existing spec-sourced vector exercises the changed path. Ask
  for vectors or approval to source them — never validate crypto by
  round-trip.
- **Stop-2: The fix belongs in hashlib or hashlib_codecs.** Report the
  cross-repo finding with file:line; do not modify sibling repos or work
  around their bugs with shims here.
- **Stop-3: Security judgment calls** — anything involving constant-time
  behavior, RNG choice, nonce reuse, default parameter security, or weakening
  validation. Present the options and trade-offs; never silently pick one.
- **Stop-4: Public API shape** — new public names, changed signatures,
  changed error types, removed/renamed exports. Propose against §3.3's naming
  table and wait for confirmation — this package has semver consumers.
- **Stop-5: Version/publish actions** — bumping `version:`, tagging, or
  anything that triggers the release pipeline, unless the request explicitly
  asked for a release.
- **Stop-6: A test looks wrong** (e.g. E1's `isNot(equals(...))`). The
  asymmetries here are usually intentional; ask before "fixing" any existing
  assertion.

**Proceed, but flag it in your summary** when:

- **Flag-1:** Code contradicts documentation (README/AGENTS/dartdoc) — trust
  the code, do the task against the code's reality, and report the doc drift.
- **Flag-2:** You find a pre-existing bug outside your task's scope — leave
  it, report file:line and a suggested fix.
- **Flag-3:** A convention is ambiguous for your case (e.g. new file doesn't
  fit an existing directory) — choose the closest analogy to an existing
  file, name the choice and the analog in your summary.

**Never** silently: commit or push (only on explicit request in the current
message, §3.6), delete tests, loosen assertions, change error types/messages,
reorder MAC input feeding, remove defensive copies, or edit generated blocks.
