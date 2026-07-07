# cipherlib

[![package version](https://img.shields.io/pub/v/cipherlib?label=pub.dev)](https://pub.dev/packages/cipherlib)
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

[![hashlib_codecs](https://img.shields.io/badge/hashlib__codecs-informational?style=for-the-badge&logo=dart)](https://pub.dev/packages/hashlib_codecs) &rarr; [![hashlib](https://img.shields.io/badge/hashlib-blue?style=for-the-badge&logo=dart)](https://pub.dev/packages/hashlib) &rarr; [![cipherlib](https://img.shields.io/badge/cipherlib-success?style=for-the-badge&logo=dart)](https://pub.dev/packages/cipherlib)

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
  cipherlib: ^0.7.0
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

<!-- file: example/aes_gcm_example.dart -->

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

<!-- file: example/chacha20_poly1305_example.dart -->

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

<!-- file: example/xchacha20_example.dart -->

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

<!-- file: example/aes_cbc_example.dart -->

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

<!-- file: example/mlkem_example.dart -->

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
    <td><code>████████████████</code> <br> <b>9.07 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>9.18 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>7.99 Gbps</b> &#127775;</td>
  </tr>
  <tr>
    <td rowspan="2">Salsa20</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>2.16 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>2.13 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>881 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 362 Mbps &#128315;<small>5.96x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 353 Mbps &#128315;<small>6.04x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 137 Mbps &#128315;<small>6.43x</small></td>
  </tr>
  <tr>
    <td>Salsa20/Poly1305</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>2.15 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>2 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>509 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>XSalsa20</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>2.15 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>2.01 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>519 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>XSalsa20/Poly1305</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>2.15 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.91 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>357 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td rowspan="2">ChaCha20</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>2.01 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.99 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>859 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 357 Mbps &#128315;<small>5.64x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 350 Mbps &#128315;<small>5.67x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 136 Mbps &#128315;<small>6.33x</small></td>
  </tr>
  <tr>
    <td rowspan="3">ChaCha20/Poly1305</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.38 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.27 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>287 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 284 Mbps &#128315;<small>4.87x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 255 Mbps &#128315;<small>4.96x</small></td>
    <td><code>████░░░░░░░░░░░░</code> <br> 65.54 Mbps &#128315;<small>4.38x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 279 Mbps &#128315;<small>4.95x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 250 Mbps &#128315;<small>5.06x</small></td>
    <td><code>██████░░░░░░░░░░</code> <br> 115 Mbps &#128315;<small>2.5x</small></td>
  </tr>
  <tr>
    <td>XChaCha20</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.97 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.88 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>501 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>XChaCha20/Poly1305</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.38 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.25 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>235 Mbps</b> &#127775;</td>
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
    <td rowspan="3">AES-128/CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.47 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.34 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>323 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>███████████████░</code> <br> 1.41 Gbps &#128315;<small>1.04x</small></td>
    <td><code>████████████░░░░</code> <br> 1.02 Gbps &#128315;<small>1.31x</small></td>
    <td><code>█████░░░░░░░░░░░</code> <br> 107 Mbps &#128315;<small>3.03x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 232 Mbps &#128315;<small>6.34x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 201 Mbps &#128315;<small>6.68x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 44.86 Mbps &#128315;<small>7.2x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-192/CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.27 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.16 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>307 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>███████████████░</code> <br> 1.22 Gbps &#128315;<small>1.04x</small></td>
    <td><code>████████████░░░░</code> <br> 894 Mbps &#128315;<small>1.3x</small></td>
    <td><code>█████░░░░░░░░░░░</code> <br> 98.81 Mbps &#128315;<small>3.1x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 200 Mbps &#128315;<small>6.35x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 177 Mbps &#128315;<small>6.55x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 39.66 Mbps &#128315;<small>7.73x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-256/CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.09 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>978 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>257 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>███████████████░</code> <br> 1.05 Gbps &#128315;<small>1.04x</small></td>
    <td><code>█████████████░░░</code> <br> 779 Mbps &#128315;<small>1.26x</small></td>
    <td><code>█████░░░░░░░░░░░</code> <br> 86.41 Mbps &#128315;<small>2.97x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 175 Mbps &#128315;<small>6.22x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 157 Mbps &#128315;<small>6.21x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 36.03 Mbps &#128315;<small>7.13x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-128/CCM</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>551 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>527 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>198 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 113 Mbps &#128315;<small>4.87x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 93.98 Mbps &#128315;<small>5.61x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 19.5 Mbps &#128315;<small>10.16x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-192/CCM</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>484 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>471 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>187 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 97.51 Mbps &#128315;<small>4.97x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 85.97 Mbps &#128315;<small>5.47x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 17.23 Mbps &#128315;<small>10.83x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-256/CCM</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>451 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>427 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>168 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 87.88 Mbps &#128315;<small>5.14x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 77.08 Mbps &#128315;<small>5.55x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 16.39 Mbps &#128315;<small>10.22x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-128/CFB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>644 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>631 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>420 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 3.87 Mbps &#128315;<small>166.45x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 109 Mbps &#128315;<small>5.81x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 42.27 Mbps &#128315;<small>9.94x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-192/CFB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>566 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>557 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>392 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 3.76 Mbps &#128315;<small>150.61x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 94.37 Mbps &#128315;<small>5.9x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 37.31 Mbps &#128315;<small>10.5x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-256/CFB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>500 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>494 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>285 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 3.76 Mbps &#128315;<small>133.13x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 82.45 Mbps &#128315;<small>5.99x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 34.22 Mbps &#128315;<small>8.32x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-128/CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.54 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.47 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>600 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>████████░░░░░░░░</code> <br> 747 Mbps &#128315;<small>2.07x</small></td>
    <td><code>██████░░░░░░░░░░</code> <br> 591 Mbps &#128315;<small>2.48x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 80.6 Mbps &#128315;<small>7.44x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 220 Mbps &#128315;<small>7.03x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 198 Mbps &#128315;<small>7.4x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 48.78 Mbps &#128315;<small>12.29x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-192/CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.32 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.28 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>576 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>████████░░░░░░░░</code> <br> 682 Mbps &#128315;<small>1.94x</small></td>
    <td><code>███████░░░░░░░░░</code> <br> 554 Mbps &#128315;<small>2.3x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 77.33 Mbps &#128315;<small>7.45x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 193 Mbps &#128315;<small>6.85x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 175 Mbps &#128315;<small>7.31x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 43.41 Mbps &#128315;<small>13.27x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-256/CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.16 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.12 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>491 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>█████████░░░░░░░</code> <br> 643 Mbps &#128315;<small>1.81x</small></td>
    <td><code>███████░░░░░░░░░</code> <br> 510 Mbps &#128315;<small>2.19x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 72.47 Mbps &#128315;<small>6.77x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 172 Mbps &#128315;<small>6.75x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 155 Mbps &#128315;<small>7.2x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 39.4 Mbps &#128315;<small>12.46x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-128/ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.5 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.34 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>343 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 249 Mbps &#128315;<small>6x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 219 Mbps &#128315;<small>6.12x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 45.36 Mbps &#128315;<small>7.57x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-192/ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.27 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.17 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>321 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 206 Mbps &#128315;<small>6.17x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 188 Mbps &#128315;<small>6.19x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 41.65 Mbps &#128315;<small>7.71x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-256/ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.13 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.03 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>276 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 188 Mbps &#128315;<small>5.99x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 166 Mbps &#128315;<small>6.2x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 38.15 Mbps &#128315;<small>7.24x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-128/GCM</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>236 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>360 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>63.56 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>██████████░░░░░░</code> <br> 149 Mbps &#128315;<small>1.59x</small></td>
    <td><code>███████████░░░░░</code> <br> 248 Mbps &#128315;<small>1.46x</small></td>
    <td><code>█████████████░░░</code> <br> 50.8 Mbps &#128315;<small>1.25x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 12.68 Mbps &#128315;<small>18.6x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 15.18 Mbps &#128315;<small>23.74x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 5.08 Mbps &#128315;<small>12.51x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-192/GCM</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>229 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>347 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>62.93 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>███████████░░░░░</code> <br> 151 Mbps &#128315;<small>1.52x</small></td>
    <td><code>███████████░░░░░</code> <br> 243 Mbps &#128315;<small>1.43x</small></td>
    <td><code>█████████████░░░</code> <br> 49.74 Mbps &#128315;<small>1.27x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 12.5 Mbps &#128315;<small>18.31x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 14.72 Mbps &#128315;<small>23.56x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 4.92 Mbps &#128315;<small>12.78x</small></td>
  </tr>
  <tr>
    <td rowspan="3">AES-256/GCM</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>222 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>332 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>60.66 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>cryptography</td>
    <td><code>██████████░░░░░░</code> <br> 142 Mbps &#128315;<small>1.56x</small></td>
    <td><code>███████████░░░░░</code> <br> 226 Mbps &#128315;<small>1.47x</small></td>
    <td><code>████████████░░░░</code> <br> 46.26 Mbps &#128315;<small>1.31x</small></td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 12.44 Mbps &#128315;<small>17.87x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 14.43 Mbps &#128315;<small>23.01x</small></td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 4.87 Mbps &#128315;<small>12.45x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-128/IGE</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.42 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.3 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>362 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 210 Mbps &#128315;<small>6.75x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 187 Mbps &#128315;<small>6.98x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 41.98 Mbps &#128315;<small>8.62x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-192/IGE</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.18 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.13 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>320 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 181 Mbps &#128315;<small>6.5x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 163 Mbps &#128315;<small>6.94x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 38.28 Mbps &#128315;<small>8.36x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-256/IGE</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.06 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>989 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>279 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 160 Mbps &#128315;<small>6.64x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 145 Mbps &#128315;<small>6.82x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 35.45 Mbps &#128315;<small>7.88x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-128/OFB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>636 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>607 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>424 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 118 Mbps &#128315;<small>5.4x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 112 Mbps &#128315;<small>5.41x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 41.69 Mbps &#128315;<small>10.17x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-192/OFB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>546 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>545 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>389 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 103 Mbps &#128315;<small>5.3x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 97.16 Mbps &#128315;<small>5.61x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 36.52 Mbps &#128315;<small>10.65x</small></td>
  </tr>
  <tr>
    <td rowspan="2">AES-256/OFB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>487 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>486 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>335 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 90.98 Mbps &#128315;<small>5.35x</small></td>
    <td><code>███░░░░░░░░░░░░░</code> <br> 85.8 Mbps &#128315;<small>5.67x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 33.45 Mbps &#128315;<small>10.02x</small></td>
  </tr>
  <tr>
    <td>AES-128/PCBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.43 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.33 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>381 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>AES-192/PCBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.26 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.17 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>335 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>AES-256/PCBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.1 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.03 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>287 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>AES-128/XTS</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.41 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.27 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>323 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>AES-192/XTS</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.19 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>1.11 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>303 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>AES-256/XTS</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.08 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>981 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>248 Mbps</b> &#127775;</td>
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
    <td><code>████████████████</code> <br> <b>1.07 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>617 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>44 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 1.99 Mbps &#128315;<small>538.17x</small></td>
    <td><code>█████████░░░░░░░</code> <br> 341 Mbps &#128315;<small>1.81x</small></td>
    <td><code>███████████████░</code> <br> 41.15 Mbps &#128315;<small>1.07x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-192 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.03 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>564 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>36.02 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 2.03 Mbps &#128315;<small>510.94x</small></td>
    <td><code>█████████░░░░░░░</code> <br> 324 Mbps &#128315;<small>1.74x</small></td>
    <td><code>███████████████░</code> <br> 33.75 Mbps &#128315;<small>1.07x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-256 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.04 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>500 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> 28.57 Mbps</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 2 Mbps &#128315;<small>519.48x</small></td>
    <td><code>██████████░░░░░░</code> <br> 315 Mbps &#128315;<small>1.59x</small></td>
    <td><code>████████████████</code> <br> <b>29.2 Mbps</b> &#128314;<small>1.02x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-128 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.06 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>628 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>45.66 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 4.18 Mbps &#128315;<small>252.72x</small></td>
    <td><code>█████████░░░░░░░</code> <br> 338 Mbps &#128315;<small>1.86x</small></td>
    <td><code>██████████████░░</code> <br> 41.02 Mbps &#128315;<small>1.11x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-192 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.06 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>548 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>34.93 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 4.11 Mbps &#128315;<small>256.65x</small></td>
    <td><code>█████████░░░░░░░</code> <br> 305 Mbps &#128315;<small>1.8x</small></td>
    <td><code>███████████████░</code> <br> 32.83 Mbps &#128315;<small>1.06x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-256 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.04 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>494 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> 28.13 Mbps</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 4.15 Mbps &#128315;<small>251.38x</small></td>
    <td><code>██████████░░░░░░</code> <br> 305 Mbps &#128315;<small>1.62x</small></td>
    <td><code>████████████████</code> <br> <b>28.78 Mbps</b> &#128314;<small>1.02x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-128 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.03 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>615 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>45.49 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███████░░░░░░░░░</code> <br> 455 Mbps &#128315;<small>2.26x</small></td>
    <td><code>█████████░░░░░░░</code> <br> 347 Mbps &#128315;<small>1.77x</small></td>
    <td><code>██████████████░░</code> <br> 40.94 Mbps &#128315;<small>1.11x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-192 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.01 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>556 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>36.35 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███████░░░░░░░░░</code> <br> 451 Mbps &#128315;<small>2.24x</small></td>
    <td><code>█████████░░░░░░░</code> <br> 329 Mbps &#128315;<small>1.69x</small></td>
    <td><code>███████████████░</code> <br> 33.75 Mbps &#128315;<small>1.08x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Twofish-256 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>1.03 Gbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>486 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> 28.26 Mbps</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>███████░░░░░░░░░</code> <br> 454 Mbps &#128315;<small>2.26x</small></td>
    <td><code>██████████░░░░░░</code> <br> 312 Mbps &#128315;<small>1.56x</small></td>
    <td><code>████████████████</code> <br> <b>28.6 Mbps</b> &#128314;<small>1.01x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-128 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>737 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>82.4 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>2.92 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 2.04 Mbps &#128315;<small>361.54x</small></td>
    <td><code>█████████████░░░</code> <br> 65.82 Mbps &#128315;<small>1.25x</small></td>
    <td><code>█████████████░░░</code> <br> 2.43 Mbps &#128315;<small>1.2x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-256 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>744 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>83.21 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>2.93 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 2.08 Mbps &#128315;<small>358.04x</small></td>
    <td><code>█████████████░░░</code> <br> 66.78 Mbps &#128315;<small>1.25x</small></td>
    <td><code>█████████████░░░</code> <br> 2.46 Mbps &#128315;<small>1.19x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-448 / ECB</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>750 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>83.23 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>2.96 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 2.08 Mbps &#128315;<small>359.73x</small></td>
    <td><code>█████████████░░░</code> <br> 66.75 Mbps &#128315;<small>1.25x</small></td>
    <td><code>█████████████░░░</code> <br> 2.46 Mbps &#128315;<small>1.2x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-128 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>720 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>83.08 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>2.94 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 4.24 Mbps &#128315;<small>169.61x</small></td>
    <td><code>█████████████░░░</code> <br> 65.86 Mbps &#128315;<small>1.26x</small></td>
    <td><code>█████████████░░░</code> <br> 2.45 Mbps &#128315;<small>1.2x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-256 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>715 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>82.79 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>2.94 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 4.14 Mbps &#128315;<small>172.72x</small></td>
    <td><code>█████████████░░░</code> <br> 65.92 Mbps &#128315;<small>1.26x</small></td>
    <td><code>█████████████░░░</code> <br> 2.45 Mbps &#128315;<small>1.2x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-448 / CBC</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>718 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>82.35 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>2.9 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█░░░░░░░░░░░░░░░</code> <br> 4.24 Mbps &#128315;<small>169.5x</small></td>
    <td><code>█████████████░░░</code> <br> 64.63 Mbps &#128315;<small>1.27x</small></td>
    <td><code>█████████████░░░</code> <br> 2.37 Mbps &#128315;<small>1.22x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-128 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>778 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>84.45 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>2.9 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█████████░░░░░░░</code> <br> 452 Mbps &#128315;<small>1.72x</small></td>
    <td><code>█████████████░░░</code> <br> 66.98 Mbps &#128315;<small>1.26x</small></td>
    <td><code>█████████████░░░</code> <br> 2.45 Mbps &#128315;<small>1.19x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-256 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>780 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>84.05 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>3.02 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█████████░░░░░░░</code> <br> 451 Mbps &#128315;<small>1.73x</small></td>
    <td><code>█████████████░░░</code> <br> 66.99 Mbps &#128315;<small>1.25x</small></td>
    <td><code>█████████████░░░</code> <br> 2.45 Mbps &#128315;<small>1.23x</small></td>
  </tr>
  <tr>
    <td rowspan="2">Blowfish-448 / CTR</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>782 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>84.76 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>3.01 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>PointyCastle</td>
    <td><code>█████████░░░░░░░</code> <br> 453 Mbps &#128315;<small>1.73x</small></td>
    <td><code>█████████████░░░</code> <br> 66.97 Mbps &#128315;<small>1.27x</small></td>
    <td><code>█████████████░░░</code> <br> 2.44 Mbps &#128315;<small>1.24x</small></td>
  </tr>
</tbody>
</table>

> This package comes on top 102 out of 108 times.

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
    <td><code>████████████████</code> <br> <b>19.95 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>202 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>161 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>pqcrypto</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 2.24 Mbps &#128315;<small>8.91x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 22.62 Mbps &#128315;<small>8.91x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 19.33 Mbps &#128315;<small>8.32x</small></td>
  </tr>
  <tr>
    <td rowspan="2">ML-KEM-768</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>12.06 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>180 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>149 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>pqcrypto</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 1.31 Mbps &#128315;<small>9.22x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 18.9 Mbps &#128315;<small>9.52x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 16.38 Mbps &#128315;<small>9.08x</small></td>
  </tr>
  <tr>
    <td rowspan="2">ML-KEM-1024</td>
    <td>cipherlib</td>
    <td><code>████████████████</code> <br> <b>7.95 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>172 Mbps</b> &#127775;</td>
    <td><code>████████████████</code> <br> <b>146 Mbps</b> &#127775;</td>
  </tr>
  <tr>
    <td>pqcrypto</td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 791 Kbps &#128315;<small>10.05x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 17.24 Mbps &#128315;<small>9.98x</small></td>
    <td><code>██░░░░░░░░░░░░░░</code> <br> 15.51 Mbps &#128315;<small>9.42x</small></td>
  </tr>
</tbody>
</table>

> This package comes on top 18 out of 18 times.

> All benchmarks are done on 36GB _Apple M3 Pro_ using compiled _exe_
>
> Dart SDK version: 3.12.2 (stable) (Tue Jun 9 01:11:39 2026 -0700) on "macos_arm64"

<!-- file: BENCHMARK.md -->

## License

BSD 3-Clause License. See the [LICENSE](LICENSE) file for details. Issues and
contributions are welcome at
[github.com/bitanon/cipherlib](https://github.com/bitanon/cipherlib).
