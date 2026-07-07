---
name: add-cipher
description: Scaffold a new cipher algorithm, AES mode, or AEAD variant end-to-end in cipherlib house style — implementation, barrel wiring, canonical test file with KAT placeholders, integration parity, benchmark, README row, and CHANGELOG entry. Use whenever adding any new algorithm to this package.
---

# Add a new cipher to cipherlib

Follow every step in order. The quality bar is AGENTS.md §5 "New algorithm";
this skill is the procedure that satisfies it. Do not skip the KAT step — a
new algorithm without spec-sourced vectors must not be merged (AGENTS.md §0).

## Step 0 — Gather inputs (ask the maintainer if any is missing)

1. **Algorithm name** and the exact spec: RFC number + section, NIST
   publication, or a pinned reference-implementation URL (libsodium commit,
   golang/crypto file). "A blog post" is not a spec.
2. **Shape** — decide the base class now:
   - Keystream/XOR symmetric (encrypt == decrypt): `StreamCipher`
     (+ `SaltedCipher` mixin if it takes an IV/nonce). Model: `ChaCha20`.
   - Encrypt ≠ decrypt: `CipherPair`/`StreamCipherPair` with separate
     `...Encrypt`/`...Decrypt` ciphers. Model: `AESInCBCMode`.
   - Authenticated: `AEADStreamCipher<Cipher, Poly1305>` attached via an
     extension. Model: `ChaCha20Poly1305`.
   - New AES block mode: one file in `lib/src/algorithms/aes_modes/`, a
     factory method on the `AES` class in `lib/src/aes.dart`. Model: `cbc.dart`.
3. **KAT source** — where the known-answer vectors come from. Preferred, in
   order: the defining RFC/NIST spec itself → Project Wycheproof → libsodium
   test suite → golang/crypto test vectors. Record the URL; it goes into a
   code comment.
4. **Valid input sizes** — exact allowed key lengths, nonce lengths, counter
   semantics (width, starting value, position in state), tag size. Write them
   down before coding; they drive the factory validation AND the validation
   tests.

## Step 1 — Implementation file

Create `lib/src/algorithms/<name>.dart` (or `aes_modes/<name>.dart`):

```dart
// Copyright (c) <current year>, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';
import 'package:cipherlib/src/utils/typed_data.dart';
import 'package:hashlib/random.dart' show randomBytes;

const int _mask32 = 0xFFFFFFFF;

/// <Name> is a ... (one-sentence description).
///
/// This implementation is based on the [<Spec-Name>][spec]
///
/// [spec]: <spec URL>
class <Name> extends StreamCipher with SaltedCipher {
  @override
  String get name => "<Name>";

  final Uint8List key;

  @override
  final Uint8List iv;

  const <Name>._(this.key, this.iv);

  /// Creates an instance with a [key] and [nonce].
  ///
  /// Parameters:
  /// - [key] : Either 16 or 32 bytes key.
  /// - [nonce] : ... bytes nonce. (Default: random)
  factory <Name>(List<int> key, [List<int>? nonce]) {
    final key8 = validateLength('key', key, {16, 32});
    nonce ??= randomBytes(/* size */);
    final nonce8 = validateLength('nonce', nonce, {/* sizes */});
    return <Name>._(key8, nonce8);
  }

  @override
  Uint8List convert(List<int> message) {
    // ...
  }

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) async* {
    // process chunks; ALWAYS `yield result.sublist(0)` — independent buffers
  }
}
```

House rules that apply here (from AGENTS.md §3.3, §4):

- No Dart syntax newer than 2.19.
- Validate in the `factory`, throw `ArgumentError.value(v, 'name', 'length
  must be ...')`. Never throw strings.
- Convert inputs to `Uint8List` exactly once at the factory boundary. If the
  spec requires the cipher to own the buffer (it will be mutated, e.g. by
  `resetIV`), copy explicitly with `.sublist(0)` — see XSalsa20's constructor.
- Hot state: `Uint32List` aliased with `Uint8List.view(state32.buffer)`;
  unrolled rounds with locals `s0..s15`; C-style loops with pre-declared ints;
  `@pragma('vm:prefer-inline')` + `@pragma('dart2js:tryInline')` on small hot
  functions. Copy the style of `algorithms/chacha20.dart` line by line.
- Cross-file internals get `$` prefix (`$otk`, `$mac`); file-private gets `_`.
- **If the cipher derives a subkey from the nonce** (X-variant pattern) or
  feeds a MAC: override `resetIV()` to re-derive everything after
  `super.resetIV()`. Missing this causes keystream reuse (AGENTS.md §4.C2).
- For AEAD: create the `<Cipher>Poly1305 extends AEADStreamCipher` class plus
  an `extension <Cipher>ExtensionForPoly1305 on <Cipher>` with a `.poly1305()`
  method.

## Step 2 — Barrel wiring

1. Create `lib/src/<name>.dart`:

   ```dart
   // Copyright (c) <year>, Sudipto Chandra
   // All rights reserved. Check LICENSE file for details.

   import 'dart:typed_data';

   import 'package:cipherlib/src/algorithms/<name>.dart';

   export 'algorithms/<name>.dart' show <Name>;

   /// One-shot convenience. (Docs: what it does, Parameters block, Both
   /// [message] transform directions if symmetric.)
   @pragma('vm:prefer-inline')
   Uint8List <name>(List<int> message, List<int> key, {List<int>? nonce}) =>
       <Name>(key, nonce).convert(message);
   ```

   Naming: top-level function is lowercase-run-together (`xchacha20poly1305`
   style). `show` lists alphabetical (`combinators_ordering` lint). AES modes
   skip this step — they get a factory method on `AES` instead.

2. Add `export '<name>.dart';` to `lib/src/cipherlib_base.dart`, keeping the
   export list alphabetical.

## Step 3 — Canonical test file

Create `test/<name>_test.dart` with the license header and this exact group
skeleton (models: `test/chacha20_test.dart`, `test/xsalsa20_poly1305_test.dart`):

```dart
void main() {
  group('validation', () {
    test('name', () { /* expect(.name, "<SpecString>") */ });
    test('accepts empty message', () { /* returns empty */ });
    test('The key should be either 16 or 32 bytes', () {
      for (int i = 0; i < 100; ++i) {
        // returnsNormally at valid sizes, throwsArgumentError otherwise,
        // always with reason: 'length: $i'
      }
    });
    // same sweep for nonce sizes; counter-rejection cases if applicable;
    test('random nonce is used if nonce is null', () { /* two calls differ */ });
    // if derived-key: 'reset iv' test asserting subkey/subnonce/keypair/tag
    //   all change while key stays; and a
    // 'constructor should not mutate caller key buffer' test
  });

  group('known inputs', () {
    // <KAT source URL + section> as a comment ABOVE each test
    test('<spec name> test vector', () {
      // fromHex inputs, compare with expect(toHex(actual), equals(toHex(expected)))
    });
  });

  group('correctness', () {
    test('encryption <-> decryption (convert)', () {
      for (int j = 0; j < 100; ++j) {
        // random key/nonce via randomBytes/randomNumbers; round-trip;
        // reason: '[size: $j]'
      }
    });
    // if it has a counter: group('counter increment', ...) crossing the
    // 32-bit and 64-bit boundaries (model: chacha20_test.dart)
  });

  group('stream support', () {
    test('bind output matches convert output across uneven chunks', () async {});
    test('bind emits independent full chunks', () async {});
    test('cast is unsupported for StreamCipher', () {});
  });
}
```

AEAD test files additionally need: sign/verify round-trip with random `aad`,
tamper → `throwsA(isA<StateError>())`, and — important — the encrypt-side and
decrypt-side macs must be asserted **different** (`isNot(equals(...))`);
`sign` MACs output, `verify` MACs input (AGENTS.md §4.E1).

Bulk vectors (more than ~5): put them in `test/fixtures/<name>_vectors.dart`
as a `List<Map<String, String>>` with hex-string values, source URL in a
comment at the top, `// ignore_for_file: non_constant_identifier_names` if the
variable name needs underscores. Model: `test/fixtures/xchacha20_vectors.dart`.

## Step 4 — Cross-library parity (if applicable)

If `pointycastle` or `cryptography` implements the algorithm:

- Add a comparison to `test/compare_test.dart` (tagged `@Tags(['vm-only'])`),
  looping over ~100 random sizes.
- Add a parity check under `test_integration/src/` and call it from
  `test_integration/main.dart` (plain assert helpers from
  `test_integration/src/assertions.dart`, not package:test).

If neither library supports it, note that in the summary and skip.

## Step 5 — Benchmark

Create `benchmark/<name>.dart` modeled on `benchmark/chacha20.dart`:
`CipherlibBenchmark extends SyncBenchmark` (+ `PointyCastleBenchmark` /
`CryptographyBenchmark` where competitors exist), deterministic inputs
(`List.filled(size, 0x3f)`), standalone `main()` over sizes
`[1 << 20, 1 << 10, 1 << 5]`. Register it in the map inside
`benchmark/benchmark.dart`. Do NOT regenerate `BENCHMARK.md` unless on the
reference M3 Pro machine — use the `benchmark` skill for that.

## Step 6 — Docs

- README "Features" table: add the row with class + top-level function names
  (only symbols that actually exist — grep first) and the Source column
  (`RFC-8439`-style).
- `CHANGELOG.md`: bullet under the unreleased/top section, `# X.Y.Z` H1 style,
  emoji prefix matching neighbors.
- Example file in `example/` if the API shape is new (model:
  `example/chacha20_example.dart`).

## Step 7 — Gate

Run the `verify` skill (or manually: `dart format --set-exit-if-changed .`,
`dart analyze --fatal-infos`, `dart test -p vm`, integration suite). All
green, KATs included, before declaring done. In the summary, list which KAT
source was used and which checklist items (AGENTS.md §5) were satisfied or
intentionally skipped.
