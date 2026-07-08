# cipherlib

[![package version](https://img.shields.io/pub/v/cipherlib?label=pub)](https://pub.dev/packages/cipherlib)
[![dart support](https://img.shields.io/badge/dart-%3E%3D%202.19.0-0175C2?logo=dart&logoColor=white)](https://dart.dev/guides/whats-new)
[![likes](https://img.shields.io/pub/likes/cipherlib?logo=dart)](https://pub.dev/packages/cipherlib/score)
[![pub points](https://img.shields.io/pub/points/cipherlib?logo=dart&color=teal)](https://pub.dev/packages/cipherlib/score)
[![codecov](https://codecov.io/gh/bitanon/cipherlib/graph/badge.svg?token=ISIYJ8MNI0)](https://codecov.io/gh/bitanon/cipherlib)
[![Test](https://github.com/bitanon/cipherlib/actions/workflows/test.yml/badge.svg)](https://github.com/bitanon/cipherlib/actions/workflows/test.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/bitanon/cipherlib)

A pure-Dart cryptography library: modern stream ciphers, authenticated
encryption, a full AES mode set, and post-quantum cryptography with no
native bindings and a single dependency.

`cipherlib` is the top layer of a three-package family:

[![convertlib](https://img.shields.io/badge/convertlib-informational?style=for-the-badge&logo=dart)](https://pub.dev/packages/convertlib) &rarr; [![hashlib](https://img.shields.io/badge/hashlib-blue?style=for-the-badge&logo=dart)](https://pub.dev/packages/hashlib) &rarr; [![cipherlib](https://img.shields.io/badge/cipherlib-success?style=for-the-badge&logo=dart)](https://pub.dev/packages/cipherlib)

It reuses `hashlib` for the SHA-3/SHAKE, Poly1305, and secure-random
primitives it is built on, and that is its only runtime dependency.

## Highlights

- **Runs on every platform**: pure Dart with no native code or FFI, so
  the same library works everywhere Dart does: the VM, Flutter (Android, iOS,
  Windows, macOS, Linux), and the web (dart2js and dart2wasm).
- **Authenticated by default**: AES-GCM, AES-CCM, and a Poly1305 variant of
  every stream cipher, each with a constant-time tag check that rejects
  tampered messages.
- **Broad AES coverage**: ten modes, from ECB and CBC to GCM, CCM, and XTS.
- **One-shot or streaming**: encrypt a buffer in a single call, or pipe a
  `Stream<List<int>>` through any cipher as a `StreamTransformer`.
- **Post-quantum ready**: ML-KEM-512/768/1024 (FIPS 203) for
  quantum-resistant key exchange.
- **Fast**: consistently outruns `PointyCastle` and `cryptography`, see in the
  [benchmarks](#benchmarks) below.

## Install

```yaml
dependencies:
  cipherlib: ^0.7.1
```

or run `dart pub add cipherlib`. A single import exposes every algorithm:

```dart
import 'package:cipherlib/cipherlib.dart';
```

Two optional companions pair well with it — `codecs` for hex/UTF-8 conversion
(re-exported from `hashlib`) and `random` for secure key and nonce generation:

```dart
import 'package:cipherlib/codecs.dart'; // toHex, fromHex, toUtf8, fromUtf8
import 'package:cipherlib/random.dart'; // randomBytes
```

Full API reference:
[cipherlib library](https://pub.dev/documentation/cipherlib/latest/cipherlib/cipherlib-library.html).

## Quickstart

AES-256-GCM is the recommended default for most applications: it encrypts and
authenticates in one step, and decryption fails loudly if the ciphertext or
the associated data bound to it was modified.

<!-- file: example/aes_gcm_example.dart -->

```dart
import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(32); // AES-256
  final nonce = randomBytes(12); // Recommended IV size for GCM
  final aad = toUtf8('order-id=INV-1001');
  final plain = toUtf8('Ship 3 units to dock-7');

  final aes = AES(key).gcm(nonce, aad: aad);
  final sealed = aes.encrypt(plain);
  final opened = aes.decrypt(sealed);

  print('AES-256-GCM');
  print('key   : ${toHex(key)}');
  print('nonce : ${toHex(nonce)}');
  print('aad   : ${fromUtf8(aad)}');
  print('cipher: ${toHex(sealed)}');
  print('plain : ${fromUtf8(opened)}');
}
```

Every snippet in this README is also a runnable program in the
[example](https://github.com/bitanon/cipherlib/tree/main/example) folder.

## Supported algorithms

### Block ciphers

| Algorithm | Public class and methods |    Source     |
| --------- | ------------------------ | :-----------: |
| AES       | `AES`                    | NIST.FIPS.197 |
| Blowfish  | `Blowfish`               | Blowfish-1993 |
| Twofish   | `Twofish`                | Twofish-1998  |

AES supports 10 modes:

- `ECB` - Electronic Codebook
- `CBC` - Cipher Block Chaining
- `CTR` - Counter
- `GCM` - Galois/Counter Mode _(authenticated)_
- `CCM` - Counter with CBC-MAC _(authenticated)_
- `CFB` - Cipher Feedback
- `OFB` - Output Feedback
- `IGE` - Infinite Garble Extension
- `PCBC` - Propagating Cipher Block Chaining
- `XTS` - XEX Tweakable Block Cipher with Ciphertext Stealing

Blowfish and Twofish support 2 modes:

- `ECB` - Electronic Codebook
- `CBC` - Cipher Block Chaining
- `CTR` - Counter

### Stream ciphers

| Algorithm | Public class and methods |    Source    |
| --------- | ------------------------ | :----------: |
| XOR       | `XOR`, `xor`             |  Wikipedia   |
| ChaCha20  | `ChaCha20`, `chacha20`   |   RFC-8439   |
| XChaCha20 | `XChaCha20`, `xchacha20` |  libsodium   |
| Salsa20   | `Salsa20`, `salsa20`     | Snuffle-2005 |
| XSalsa20  | `XSalsa20`, `xsalsa20`   |  libsodium   |

### Authenticated encryption (AEAD)

| Algorithm          | Public class and methods                 |    Source    |
| ------------------ | ---------------------------------------- | :----------: |
| ChaCha20/Poly1305  | `ChaCha20Poly1305`, `chacha20poly1305`   |   RFC-8439   |
| XChaCha20/Poly1305 | `XChaCha20Poly1305`, `xchacha20poly1305` |  libsodium   |
| Salsa20/Poly1305   | `Salsa20Poly1305`, `salsa20poly1305`     | Snuffle-2005 |
| XSalsa20/Poly1305  | `XSalsa20Poly1305`, `xsalsa20poly1305`   |  libsodium   |

AES adds authenticated encryption through its `GCM` and `CCM` modes.

### Post-Quantum Cryptography

| Algorithm | Public class and methods |    Source     |
| --------- | ------------------------ | :-----------: |
| ML-KEM    | `MLKEM`                  | NIST.FIPS.203 |

`MLKEM.kem512()`, `MLKEM.kem768()`, and `MLKEM.kem1024()` provide key
generation, encapsulation, and decapsulation, with optional deterministic key
generation from a 64-byte seed.

## Security notes

- **Never reuse a `(key, nonce)` pair.** For the stream ciphers and for
  AES-CTR/GCM/CCM, encrypting two messages under the same key and nonce
  destroys confidentiality — and for GCM/CCM it also lets an attacker forge
  tags. Use a fresh random nonce (or a strictly increasing counter) per
  message; XChaCha20/XSalsa20's 24-byte nonce is large enough to randomize
  safely.
- **AES is not constant-time.** The pure-Dart AES uses table lookups, which
  are not guaranteed to run in constant time. Weigh the deployment environment
  before using it where cache-timing side channels matter.
- **ML-KEM timing.** The implementation follows the constant-time structure of
  the reference implementation, but Dart runtimes (JIT, AOT, dart2js) cannot
  guarantee constant-time execution. Consider the deployment environment before
  using ML-KEM in side-channel-sensitive settings.

## Recipes

### ChaCha20-Poly1305

A fast software AEAD, well suited to mobile and network protocols. The one-shot
function returns both the ciphertext (`.data`) and the tag (`.mac`); pass the
tag back on decryption and a mismatch throws.

<!-- file: example/chacha20_poly1305_example.dart -->

```dart
import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(32);
  final nonce = randomBytes(12);
  final aad = toUtf8('content-type=application/json');
  final message = toUtf8('{"event":"payment.settled","id":42}');

  final sealed = chacha20poly1305(
    message,
    key,
    nonce: nonce,
    aad: aad,
  );

  final opened = chacha20poly1305(
    sealed.data,
    key,
    nonce: nonce,
    aad: aad,
    mac: sealed.mac.bytes,
  );

  print('ChaCha20-Poly1305');
  print('key   : ${toHex(key)}');
  print('nonce : ${toHex(nonce)}');
  print('tag   : ${sealed.mac.hex()}');
  print('cipher: ${toHex(sealed.data)}');
  print('plain : ${fromUtf8(opened.data)}');
}
```

### XChaCha20 (extended nonce)

XChaCha20 widens the nonce to 24 bytes, so a random nonce per message is safe
without tracking a counter. Append `poly1305` (`xchacha20poly1305`) for the
authenticated variant.

<!-- file: example/xchacha20_example.dart -->

```dart
import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(32);
  final nonce = randomBytes(24); // Extended nonce
  final plain = toUtf8('XChaCha20 extended nonce payload');

  final cipher = xchacha20(plain, key, nonce: nonce);
  final opened = xchacha20(cipher, key, nonce: nonce);

  print('XChaCha20');
  print('key   : ${toHex(key)}');
  print('nonce : ${toHex(nonce)}');
  print('cipher: ${toHex(cipher)}');
  print('plain : ${fromUtf8(opened)}');
}
```

### AES-CBC with PKCS#7 padding

For interoperability with systems that expect classic block modes. `AES.pkcs7`
adds and strips padding automatically, and `encryptString`/`decrypt` handle the
UTF-8 conversion.

<!-- file: example/aes_cbc_example.dart -->

```dart
import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(32);
  final iv = randomBytes(16);
  final plain = 'Confidential invoice payload';

  // PKCS7 is the common padding choice for block modes like CBC.
  final cbc = AES.pkcs7(key).cbc(iv);
  final cipher = cbc.encryptString(plain);
  final opened = cbc.decrypt(cipher);

  print('AES-256-CBC + PKCS7');
  print('key   : ${toHex(key)}');
  print('iv    : ${toHex(iv)}');
  print('cipher: ${toHex(cipher)}');
  print('plain : ${fromUtf8(opened)}');
}
```

### Streaming large data

Every stream cipher is a `StreamTransformer<List<int>, Uint8List>`, so a
`Stream<List<int>>` can be piped through `cipher.bind(...)` (or
`stream.transform(cipher)`) and processed chunk by chunk without buffering the
whole message in memory:

```dart
import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

Future<void> main() async {
  final key = randomBytes(32);
  final nonce = randomBytes(12);
  final chacha = ChaCha20(key, nonce);

  final plainChunks = Stream<List<int>>.fromIterable([
    toUtf8('a streamed '),
    toUtf8('message'),
  ]);

  await for (final encrypted in chacha.bind(plainChunks)) {
    print(toHex(encrypted));
  }
}
```

For byte-by-byte `Stream<int>` sources, use the `stream()` extension instead of
`bind`.

### Detecting tampering

Authenticated ciphers reject modified input instead of returning garbage —
flipping a single bit of the tag makes decryption throw a `StateError`:

```dart
import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(32);
  final nonce = randomBytes(24);
  final sealed = xchacha20poly1305(
    toUtf8('integrity protected'),
    key,
    nonce: nonce,
  );

  // Flip one bit of the tag to simulate tampering in transit.
  final badTag = List<int>.from(sealed.mac.bytes)..[0] ^= 0xff;

  try {
    xchacha20poly1305(sealed.data, key, nonce: nonce, mac: badTag);
    print('accepted (unexpected)');
  } on StateError catch (e) {
    print('rejected: ${e.message}');
  }
}
```

### Post-quantum key exchange (ML-KEM)

Two parties agree on a shared secret that stays safe even against an attacker
with a quantum computer. Alice publishes her encapsulation key; Bob derives a
shared secret and a ciphertext from it; Alice recovers the same secret from the
ciphertext.

<!-- file: example/mlkem_example.dart -->

```dart
import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';

void main() {
  final kem = MLKEM.kem768();

  // Alice generates a key pair and publishes the encapsulation key
  final alice = kem.keygen();

  // Bob encapsulates a shared secret with Alice's public key and
  // transmits the ciphertext back to Alice
  final bob = kem.encaps(alice.encapsulationKey);

  // Alice recovers the same shared secret from the ciphertext
  final shared = kem.decaps(alice.decapsulationKey, bob.cipherText);

  print(kem.name);
  print('bob   : ${bob.sharedSecret.hex()}');
  print('alice : ${shared.hex()}');
  print('match : ${shared.isEqual(bob.sharedSecret)}');

  // A key pair can be stored as its 64-byte seed and re-derived later
  final seed = List.generate(64, (i) => i);
  final first = kem.keygen(seed: seed);
  final again = kem.keygen(seed: seed);
  final isSeeded =
      toHex(first.encapsulationKey) == toHex(again.encapsulationKey);
  print('seeded: $isSeeded');
}
```

The shared secret is a `HashDigest`; compare it with `isEqual` (constant-time)
rather than `==`, and derive symmetric keys from it with a KDF. A tampered
ciphertext does not throw — ML-KEM performs _implicit rejection_ and returns a
deterministic but unrelated secret, so the two sides simply fail to agree.

<!-- file: BENCHMARK.md -->

## Benchmarks

### Libraries

- **Cipherlib** : https://pub.dev/packages/cipherlib
- **PointyCastle** : https://pub.dev/packages/pointycastle
- **Cryptography** : https://pub.dev/packages/cryptography
- **PQCrypto** : https://pub.dev/packages/pqcrypto

### Stream Ciphers

<table>
<thead>
  <tr>
    <th>Algorithm</th>
    <th>Library</th>
    <th>1MB message</th>
    <th>1KB message</th>
    <th>32B message</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>XOR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>10.85 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>11.1 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>9.49 Gbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td rowspan="2">Salsa20</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>2.17 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2.13 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>909 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>351 Mbps &#128315;6.17x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>344 Mbps &#128315;6.2x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>133 Mbps &#128315;6.84x</small></td>
  </tr>
  <tr>
    <td>Salsa20 / Poly1305</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>2.16 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2.02 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>509 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>XSalsa20</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>2.16 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2.01 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>517 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>XSalsa20 / Poly1305</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>2.16 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.92 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>360 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td rowspan="2">ChaCha20</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>2.02 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>856 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>354 Mbps &#128315;5.69x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>348 Mbps &#128315;5.74x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>135 Mbps &#128315;6.33x</small></td>
  </tr>
  <tr>
    <td rowspan="3">ChaCha20 / Poly1305</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.38 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.26 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>293 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>283 Mbps &#128315;4.87x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>258 Mbps &#128315;4.89x</small></td>
    <td><code>████░░░░░░░░░░░░</code> <br> <small>66.66 Mbps &#128315;4.4x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>275 Mbps &#128315;5.01x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>256 Mbps &#128315;4.93x</small></td>
    <td><code>██████░░░░░░░░░░</code> <br> <small>116 Mbps &#128315;2.53x</small></td>
  </tr>
  <tr>
    <td>XChaCha20</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>2.01 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.88 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>502 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>XChaCha20 / Poly1305</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.38 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.25 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>235 Mbps</b> &#127775;</small></td>
  </tr>
</tbody>
</table>

> This package comes on top 39 out of 39 times.

### AES

<table>
<thead>
  <tr>
    <th>Algorithm</th>
    <th>Library</th>
    <th>1MB message</th>
    <th>1KB message</th>
    <th>32B message</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td rowspan="3">AES-128 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.46 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.33 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>338 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>███████████████░</code> <br> <small>1.41 Gbps &#128315;1.04x</small></td>
    <td><code>████████████░░░░</code> <br> <small>1.02 Gbps &#128315;1.31x</small></td>
    <td><code>█████░░░░░░░░░░░</code> <br> <small>107 Mbps &#128315;3.16x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>231 Mbps &#128315;6.3x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>203 Mbps &#128315;6.53x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>44.35 Mbps &#128315;7.61x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-192 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.26 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.16 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>310 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>███████████████░</code> <br> <small>1.21 Gbps &#128315;1.04x</small></td>
    <td><code>████████████░░░░</code> <br> <small>889 Mbps &#128315;1.31x</small></td>
    <td><code>█████░░░░░░░░░░░</code> <br> <small>95.84 Mbps &#128315;3.23x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>201 Mbps &#128315;6.27x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>177 Mbps &#128315;6.57x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>39.48 Mbps &#128315;7.84x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-256 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.11 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.02 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>269 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>███████████████░</code> <br> <small>1.06 Gbps &#128315;1.05x</small></td>
    <td><code>████████████░░░░</code> <br> <small>783 Mbps &#128315;1.3x</small></td>
    <td><code>█████░░░░░░░░░░░</code> <br> <small>86.94 Mbps &#128315;3.09x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>178 Mbps &#128315;6.22x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>157 Mbps &#128315;6.47x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>36.37 Mbps &#128315;7.39x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-128 / CCM</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>554 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>524 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>201 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>112 Mbps &#128315;4.96x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>97.2 Mbps &#128315;5.39x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>19.61 Mbps &#128315;10.24x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-192 / CCM</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>492 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>468 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>185 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>98.09 Mbps &#128315;5.01x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>84.71 Mbps &#128315;5.52x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>16.54 Mbps &#128315;11.21x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-256 / CCM</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>446 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>423 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>165 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>86.9 Mbps &#128315;5.13x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>75.36 Mbps &#128315;5.61x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>15.38 Mbps &#128315;10.76x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-128 / CFB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>639 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>629 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>415 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>3.66 Mbps &#128315;174.44x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>107 Mbps &#128315;5.9x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>41.37 Mbps &#128315;10.03x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-192 / CFB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>558 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>546 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>385 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>3.64 Mbps &#128315;153.4x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>92.26 Mbps &#128315;5.92x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>36.57 Mbps &#128315;10.53x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-256 / CFB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>504 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>494 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>330 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>3.61 Mbps &#128315;139.45x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>82.72 Mbps &#128315;5.97x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>33.51 Mbps &#128315;9.85x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-128 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.51 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.46 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>596 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>████████░░░░░░░░</code> <br> <small>734 Mbps &#128315;2.05x</small></td>
    <td><code>██████░░░░░░░░░░</code> <br> <small>579 Mbps &#128315;2.52x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>77.12 Mbps &#128315;7.73x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>219 Mbps &#128315;6.88x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>196 Mbps &#128315;7.44x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>47.99 Mbps &#128315;12.42x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-192 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.31 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.27 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>570 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>████████░░░░░░░░</code> <br> <small>680 Mbps &#128315;1.93x</small></td>
    <td><code>███████░░░░░░░░░</code> <br> <small>545 Mbps &#128315;2.34x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>76.02 Mbps &#128315;7.5x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>193 Mbps &#128315;6.82x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>172 Mbps &#128315;7.41x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>42.99 Mbps &#128315;13.26x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-256 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.15 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.11 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>489 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>█████████░░░░░░░</code> <br> <small>634 Mbps &#128315;1.82x</small></td>
    <td><code>███████░░░░░░░░░</code> <br> <small>513 Mbps &#128315;2.17x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>73.71 Mbps &#128315;6.63x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>171 Mbps &#128315;6.77x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>154 Mbps &#128315;7.22x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>40.13 Mbps &#128315;12.17x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-128 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.49 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.35 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>350 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>249 Mbps &#128315;5.97x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>217 Mbps &#128315;6.2x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>46.89 Mbps &#128315;7.46x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-192 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.28 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.17 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>322 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>215 Mbps &#128315;5.94x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>189 Mbps &#128315;6.2x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>41.35 Mbps &#128315;7.79x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-256 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.12 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.03 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>278 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>189 Mbps &#128315;5.96x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>167 Mbps &#128315;6.17x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>37.92 Mbps &#128315;7.34x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-128 / GCM</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>237 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>352 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>63.12 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>███████████░░░░░</code> <br> <small>157 Mbps &#128315;1.51x</small></td>
    <td><code>███████████░░░░░</code> <br> <small>250 Mbps &#128315;1.41x</small></td>
    <td><code>█████████████░░░</code> <br> <small>49.76 Mbps &#128315;1.27x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>12.67 Mbps &#128315;18.71x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>15.58 Mbps &#128315;22.57x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>5.09 Mbps &#128315;12.39x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-192 / GCM</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>233 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>350 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>61.76 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>███████████░░░░░</code> <br> <small>158 Mbps &#128315;1.47x</small></td>
    <td><code>███████████░░░░░</code> <br> <small>244 Mbps &#128315;1.43x</small></td>
    <td><code>████████████░░░░</code> <br> <small>48.22 Mbps &#128315;1.28x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>12.59 Mbps &#128315;18.47x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>15.24 Mbps &#128315;22.96x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>4.94 Mbps &#128315;12.51x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-256 / GCM</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>226 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>333 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>60.5 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>███████████░░░░░</code> <br> <small>151 Mbps &#128315;1.5x</small></td>
    <td><code>███████████░░░░░</code> <br> <small>229 Mbps &#128315;1.45x</small></td>
    <td><code>████████████░░░░</code> <br> <small>45.65 Mbps &#128315;1.33x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>12.45 Mbps &#128315;18.18x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>15.25 Mbps &#128315;21.83x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>4.95 Mbps &#128315;12.23x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-128 / IGE</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.41 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.3 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>356 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>210 Mbps &#128315;6.73x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>186 Mbps &#128315;6.99x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>43.57 Mbps &#128315;8.17x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-192 / IGE</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.23 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.14 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>329 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>184 Mbps &#128315;6.65x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>164 Mbps &#128315;6.92x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>38.67 Mbps &#128315;8.51x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-256 / IGE</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.08 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>998 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>286 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>165 Mbps &#128315;6.52x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>148 Mbps &#128315;6.76x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>35.75 Mbps &#128315;8x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-128 / OFB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>637 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>628 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>425 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>120 Mbps &#128315;5.31x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>113 Mbps &#128315;5.54x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>42.35 Mbps &#128315;10.03x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-192 / OFB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>550 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>552 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>396 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>104 Mbps &#128315;5.3x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>97.81 Mbps &#128315;5.64x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>37.25 Mbps &#128315;10.64x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-256 / OFB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>500 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>494 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>341 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>91.42 Mbps &#128315;5.47x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> <small>86.64 Mbps &#128315;5.7x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>34.42 Mbps &#128315;9.92x</small></td>
  </tr>
  <tr>
    <td>AES-128 / PCBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.45 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.34 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>383 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>AES-192 / PCBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.25 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.17 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>347 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>AES-256 / PCBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.11 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.03 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>298 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>AES-128 / XTS</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.42 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.29 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>333 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>AES-192 / XTS</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.23 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>1.13 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>265 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>AES-256 / XTS</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.09 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>978 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>256 Mbps</b> &#127775;</small></td>
  </tr>
</tbody>
</table>

> This package comes on top 189 out of 189 times.

### Blowfish & Twofish

<table>
<thead>
  <tr>
    <th>Algorithm</th>
    <th>Library</th>
    <th>1MB message</th>
    <th>1KB message</th>
    <th>32B message</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td rowspan="2">Twofish-128 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.08 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>638 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>45.85 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>1.84 Mbps &#128315;585.2x</small></td>
    <td><code>█████████░░░░░░░</code> <br> <small>339 Mbps &#128315;1.88x</small></td>
    <td><code>███████████████░</code> <br> <small>41.74 Mbps &#128315;1.1x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-192 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.06 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>567 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>36.05 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>1.8 Mbps &#128315;590.1x</small></td>
    <td><code>█████████░░░░░░░</code> <br> <small>321 Mbps &#128315;1.76x</small></td>
    <td><code>███████████████░</code> <br> <small>34.12 Mbps &#128315;1.06x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-256 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.07 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>499 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small>28.31 Mbps </small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>1.83 Mbps &#128315;582.99x</small></td>
    <td><code>██████████░░░░░░</code> <br> <small>304 Mbps &#128315;1.64x</small></td>
    <td><code>████████████████</code> <br> <small><b>28.97 Mbps</b> &#128314;1.02x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-128 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.06 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>632 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>46.42 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>3.62 Mbps &#128315;291.97x</small></td>
    <td><code>████████░░░░░░░░</code> <br> <small>325 Mbps &#128315;1.94x</small></td>
    <td><code>██████████████░░</code> <br> <small>40.59 Mbps &#128315;1.14x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-192 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.05 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>560 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>36.14 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>3.6 Mbps &#128315;291.63x</small></td>
    <td><code>█████████░░░░░░░</code> <br> <small>307 Mbps &#128315;1.82x</small></td>
    <td><code>███████████████░</code> <br> <small>33.4 Mbps &#128315;1.08x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-256 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.05 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>496 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small>28.23 Mbps </small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>3.67 Mbps &#128315;286.45x</small></td>
    <td><code>█████████░░░░░░░</code> <br> <small>293 Mbps &#128315;1.69x</small></td>
    <td><code>████████████████</code> <br> <small><b>28.36 Mbps</b> &#128314;1x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-128 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.03 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>619 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>46.41 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███████░░░░░░░░░</code> <br> <small>422 Mbps &#128315;2.43x</small></td>
    <td><code>████████░░░░░░░░</code> <br> <small>328 Mbps &#128315;1.89x</small></td>
    <td><code>██████████████░░</code> <br> <small>40.26 Mbps &#128315;1.15x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-192 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.03 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>556 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>35.99 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███████░░░░░░░░░</code> <br> <small>426 Mbps &#128315;2.42x</small></td>
    <td><code>█████████░░░░░░░</code> <br> <small>311 Mbps &#128315;1.79x</small></td>
    <td><code>███████████████░</code> <br> <small>33.26 Mbps &#128315;1.08x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-256 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>1.04 Gbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>491 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>28.32 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███████░░░░░░░░░</code> <br> <small>427 Mbps &#128315;2.42x</small></td>
    <td><code>██████████░░░░░░</code> <br> <small>295 Mbps &#128315;1.66x</small></td>
    <td><code>████████████████</code> <br> <small>28.15 Mbps &#128315;1.01x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-128 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>755 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>77.07 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2.81 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>1.82 Mbps &#128315;414.53x</small></td>
    <td><code>█████████████░░░</code> <br> <small>64.66 Mbps &#128315;1.19x</small></td>
    <td><code>██████████████░░</code> <br> <small>2.4 Mbps &#128315;1.17x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-256 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>760 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>78.54 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2.62 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>1.77 Mbps &#128315;429.53x</small></td>
    <td><code>█████████████░░░</code> <br> <small>63.87 Mbps &#128315;1.23x</small></td>
    <td><code>███████████████░</code> <br> <small>2.38 Mbps &#128315;1.1x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-448 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>707 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>78.69 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2.74 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>1.77 Mbps &#128315;399.76x</small></td>
    <td><code>█████████████░░░</code> <br> <small>64.31 Mbps &#128315;1.22x</small></td>
    <td><code>██████████████░░</code> <br> <small>2.34 Mbps &#128315;1.17x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-128 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>699 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>76.81 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2.69 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>3.45 Mbps &#128315;202.76x</small></td>
    <td><code>█████████████░░░</code> <br> <small>62.03 Mbps &#128315;1.24x</small></td>
    <td><code>██████████████░░</code> <br> <small>2.3 Mbps &#128315;1.17x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-256 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>689 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>77.55 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2.72 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>3.52 Mbps &#128315;195.93x</small></td>
    <td><code>█████████████░░░</code> <br> <small>61.94 Mbps &#128315;1.25x</small></td>
    <td><code>██████████████░░</code> <br> <small>2.34 Mbps &#128315;1.16x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-448 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>699 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>79.48 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2.63 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> <small>3.48 Mbps &#128315;200.51x</small></td>
    <td><code>█████████████░░░</code> <br> <small>62.34 Mbps &#128315;1.28x</small></td>
    <td><code>██████████████░░</code> <br> <small>2.29 Mbps &#128315;1.15x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-128 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>763 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>78.47 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2.79 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>████████░░░░░░░░</code> <br> <small>403 Mbps &#128315;1.9x</small></td>
    <td><code>█████████████░░░</code> <br> <small>62.67 Mbps &#128315;1.25x</small></td>
    <td><code>█████████████░░░</code> <br> <small>2.33 Mbps &#128315;1.2x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-256 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>767 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>78.86 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2.82 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>████████░░░░░░░░</code> <br> <small>406 Mbps &#128315;1.89x</small></td>
    <td><code>█████████████░░░</code> <br> <small>64.4 Mbps &#128315;1.22x</small></td>
    <td><code>██████████████░░</code> <br> <small>2.39 Mbps &#128315;1.18x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-448 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>787 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>81.16 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>2.78 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>████████░░░░░░░░</code> <br> <small>413 Mbps &#128315;1.91x</small></td>
    <td><code>█████████████░░░</code> <br> <small>64.71 Mbps &#128315;1.25x</small></td>
    <td><code>██████████████░░</code> <br> <small>2.37 Mbps &#128315;1.17x</small></td>
  </tr>
</tbody>
</table>

> This package comes on top 104 out of 108 times.

### Key Encapsulation

<table>
<thead>
  <tr>
    <th>Algorithm</th>
    <th>Library</th>
    <th>Key Generation</th>
    <th>Encapsulation</th>
    <th>Decapsulation</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td rowspan="2">ML-KEM-512</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>20.1 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>204 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>165 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>pqcrypto</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>2.29 Mbps &#128315;8.77x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>22.76 Mbps &#128315;8.95x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>20.18 Mbps &#128315;8.17x</small></td>
  </tr>
  <tr>
    <td rowspan="2">ML-KEM-768</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>12.4 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>183 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>153 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>pqcrypto</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>1.34 Mbps &#128315;9.23x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>19.13 Mbps &#128315;9.59x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>16.92 Mbps &#128315;9.04x</small></td>
  </tr>
  <tr>
    <td rowspan="2">ML-KEM-1024</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <small><b>8.11 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>179 Mbps</b> &#127775;</small></td>
    <td><code>████████████████</code> <br> <small><b>152 Mbps</b> &#127775;</small></td>
  </tr>
  <tr>
    <td>pqcrypto</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>824 Kbps &#128315;9.84x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>17.7 Mbps &#128315;10.11x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> <small>15.97 Mbps &#128315;9.5x</small></td>
  </tr>
</tbody>
</table>

> This package comes on top 18 out of 18 times.

> All benchmarks are done on 36GB _Apple M3 Pro_ using compiled _exe_
>
> Dart SDK version: 3.12.2 (stable) (Tue Jun 9 01:11:39 2026 -0700) on "macos_arm64"

## License

BSD 3-Clause License. See the [LICENSE](LICENSE) file for details. Issues and
contributions are welcome at
[github.com/bitanon/cipherlib](https://github.com/bitanon/cipherlib).
