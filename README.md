# cipherlib

[![package version](https://img.shields.io/pub/v/cipherlib?label=pub.dev)](https://pub.dev/packages/cipherlib)
[![dart support](https://img.shields.io/badge/dart-%3E%3D%202.19.0-0175C2?logo=dart&logoColor=white)](https://dart.dev/guides/whats-new)
[![likes](https://img.shields.io/pub/likes/cipherlib?logo=dart)](https://pub.dev/packages/cipherlib/score)
[![pub points](https://img.shields.io/pub/points/cipherlib?logo=dart&color=teal)](https://pub.dev/packages/cipherlib/score)
[![codecov](https://codecov.io/gh/bitanon/cipherlib/graph/badge.svg?token=ISIYJ8MNI0)](https://codecov.io/gh/bitanon/cipherlib)
[![Test](https://github.com/bitanon/cipherlib/actions/workflows/test.yml/badge.svg)](https://github.com/bitanon/cipherlib/actions/workflows/test.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/bitanon/cipherlib)

A pure-Dart symmetric cryptography library with modern stream ciphers, AEAD support, and a broad AES mode set.

`cipherlib` provides AES (multiple modes), ChaCha20/XChaCha20, Salsa20/XSalsa20, XOR, and Poly1305-based AEAD variants. The only runtime dependency is [`hashlib`](https://pub.dev/packages/hashlib).

## At a glance

- Pure Dart implementation with no native bindings.
- One-shot and stream APIs for common cipher workflows.
- Broad AES mode coverage, including GCM and XTS.
- Modern AEAD options: ChaCha20-Poly1305, XChaCha20-Poly1305, Salsa20-Poly1305, XSalsa20-Poly1305.
- Cross-library comparisons and benchmark data included.

## Features

| Ciphers            | Public class and methods                    |    Source     |
| ------------------ | ------------------------------------------- | :-----------: |
| AES                | `AES`                                      | NIST.FIPS.197 |
| XOR                | `XOR`, `xor`, `xorStream`                   |   Wikipedia   |
| ChaCha20           | `ChaCha20`, `chacha20`, `chacha20Stream`    |   RFC-8439    |
| ChaCha20/Poly1305  | `ChaCha20Poly1305`, `chacha20poly1305`      |   RFC-8439    |
| XChaCha20          | `XChaCha20`, `xchacha20`, `xchacha20Stream` |   libsodium   |
| XChaCha20/Poly1305 | `XChaCha20Poly1305`, `xchacha20poly1305`    |   libsodium   |
| Salsa20            | `Salsa20`, `salsa20`, `salsa20Stream`       | Snuffle-2005  |
| Salsa20/Poly1305   | `Salsa20Poly1305`, `salsa20poly1305`        | Snuffle-2005  |
| XSalsa20           | `XSalsa20`, `xsalsa20`, `xsalsa20Stream`    |   libsodium   |
| XSalsa20/Poly1305  | `XSalsa20Poly1305`, `xsalsa20poly1305`      |   libsodium   |

Available modes for AES:

- `ECB` : Electronic Codeblock
- `CBC` : Cipher Block Chaining
- `CTR` : Counter
- `GCM` : Galois/Counter Mode
- `CFB` : Cipher Feedback
- `OFB` : Output Feedback
- `IGE` : Infinite Garble Extension
- `PCBC` : Propagating Cipher Block Chaining
- `XTS` : XEX (XOR-Encrypt-XOR) Tweakable Block Cipher with Ciphertext Stealing

## Getting started

The following import will give you access to all of the algorithms in this package.

```dart
import 'package:cipherlib/cipherlib.dart';
```

API docs: [cipherlib library reference](https://pub.dev/documentation/cipherlib/latest/cipherlib/cipherlib-library.html)

## Usage

Start with the full runnable examples in [example](https://github.com/bitanon/cipherlib/tree/main/example) folder.

<!-- file: example/cipherlib_example.dart -->

```dart
import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  print('----- AES -----');
  {
    var plain = 'A not very secret message';
    var key = randomBytes(32);
    var iv = randomBytes(16);
    print('  Text: $plain');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(iv)}');
    // different modes
    print('  ECB: ${toHex(AES(key).ecb().encryptString(plain))}');
    print('  CBC: ${toHex(AES(key).cbc(iv).encryptString(plain))}');
    print('  CTR: ${toHex(AES(key).ctr(iv).encryptString(plain))}');
    print('  GCM: ${toHex(AES(key).gcm(iv).encryptString(plain))}');
    print('  CFB: ${toHex(AES(key).cfb(iv).encryptString(plain))}');
    print('  OFB: ${toHex(AES(key).ofb(iv).encryptString(plain))}');
    print('  XTS: ${toHex(AES(key).xts(iv).encryptString(plain))}');
    print('  IGE: ${toHex(AES(key).ige(iv).encryptString(plain))}');
    print(' PCBC: ${toHex(AES(key).pcbc(iv).encryptString(plain))}');
  }
  print('');

  print('----- XChaCha20 -----');
  {
    var text = "Hide me!";
    var key = randomBytes(32);
    var nonce = randomBytes(24);
    // encrypt and sign
    var cipher = xchacha20poly1305(
      toUtf8(text),
      key,
      nonce: nonce,
    );
    // verify and decrypt
    var plain = xchacha20poly1305(
      cipher.data,
      key,
      nonce: nonce,
      mac: cipher.tag.bytes,
    );
    print('  Text: $text');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(nonce)}');
    print('Cipher: ${toHex(cipher.data)}');
    print('   Tag: ${cipher.tag.hex()}');
    print(' Plain: ${fromUtf8(plain.data)}');
  }
  print('');
}
```

<!-- file: example/cipherlib_example.dart -->

<!-- file: BENCHMARK.md -->

# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib
- **PointyCastle** : https://pub.dev/packages/pointycastle
- **Cryptography** : https://pub.dev/packages/cryptography

With 1MB message:

| Algorithms         | `cipherlib`   | `PointyCastle`                | `cryptography`              |
| ------------------ | ------------- | ----------------------------- | --------------------------- |
| XOR                | **9.1 Gbps**  |                               |                             |
| Salsa20            | **2.16 Gbps** | 356 Mbps <br> `6.07x slow`    |                             |
| Salsa20/Poly1305   | **2.16 Gbps** |                               |                             |
| XSalsa20           | **2.16 Gbps** |                               |                             |
| XSalsa20/Poly1305  | **2.15 Gbps** |                               |                             |
| ChaCha20           | **2.01 Gbps** | 359 Mbps <br> `5.61x slow`    |                             |
| ChaCha20/Poly1305  | **1.21 Gbps** | 279 Mbps <br> `4.33x slow`    | 283 Mbps <br> `4.26x slow`  |
| XChaCha20          | **2.01 Gbps** |                               |                             |
| XChaCha20/Poly1305 | **1.21 Gbps** |                               |                             |
| AES-128/CBC        | **1.47 Gbps** | 234 Mbps <br> `6.29x slow`    | 1.41 Gbps <br> `1.05x slow` |
| AES-192/CBC        | **1.27 Gbps** | 203 Mbps <br> `6.28x slow`    | 1.22 Gbps <br> `1.05x slow` |
| AES-256/CBC        | **1.12 Gbps** | 181 Mbps <br> `6.22x slow`    | 1.07 Gbps <br> `1.05x slow` |
| AES-128/CFB        | **646 Mbps**  | 4.04 Mbps <br> `159.66x slow` |                             |
| AES-192/CFB        | **568 Mbps**  | 4.09 Mbps <br> `138.91x slow` |                             |
| AES-256/CFB        | **506 Mbps**  | 4.06 Mbps <br> `124.59x slow` |                             |
| AES-128/CTR        | **1.55 Gbps** | 223 Mbps <br> `6.96x slow`    | 746 Mbps <br> `2.08x slow`  |
| AES-192/CTR        | **1.34 Gbps** | 195 Mbps <br> `6.84x slow`    | 690 Mbps <br> `1.94x slow`  |
| AES-256/CTR        | **1.17 Gbps** | 174 Mbps <br> `6.73x slow`    | 642 Mbps <br> `1.82x slow`  |
| AES-128/ECB        | **1.5 Gbps**  | 250 Mbps <br> `6.03x slow`    |                             |
| AES-192/ECB        | **1.29 Gbps** | 215 Mbps <br> `5.99x slow`    |                             |
| AES-256/ECB        | **1.12 Gbps** | 189 Mbps <br> `5.96x slow`    |                             |
| AES-128/GCM        | **232 Mbps**  | 12.7 Mbps <br> `18.27x slow`  | 154 Mbps <br> `1.51x slow`  |
| AES-192/GCM        | **226 Mbps**  | 12.61 Mbps <br> `17.95x slow` | 154 Mbps <br> `1.46x slow`  |
| AES-256/GCM        | **221 Mbps**  | 12.49 Mbps <br> `17.7x slow`  | 146 Mbps <br> `1.51x slow`  |
| AES-128/IGE        | **1.43 Gbps** | 212 Mbps <br> `6.74x slow`    |                             |
| AES-192/IGE        | **1.24 Gbps** | 187 Mbps <br> `6.63x slow`    |                             |
| AES-256/IGE        | **1.09 Gbps** | 166 Mbps <br> `6.55x slow`    |                             |
| AES-128/OFB        | **641 Mbps**  | 122 Mbps <br> `5.25x slow`    |                             |
| AES-192/OFB        | **560 Mbps**  | 106 Mbps <br> `5.31x slow`    |                             |
| AES-256/OFB        | **503 Mbps**  | 93.16 Mbps <br> `5.4x slow`   |                             |
| AES-128/PCBC       | **1.47 Gbps** |                               |                             |
| AES-192/PCBC       | **1.27 Gbps** |                               |                             |
| AES-256/PCBC       | **1.12 Gbps** |                               |                             |
| AES-128/XTS        | **1.42 Gbps** |                               |                             |
| AES-192/XTS        | **1.24 Gbps** |                               |                             |
| AES-256/XTS        | **1.1 Gbps**  |                               |                             |

With 1KB message:

| Algorithms         | `cipherlib`   | `PointyCastle`                | `cryptography`              |
| ------------------ | ------------- | ----------------------------- | --------------------------- |
| XOR                | **9.22 Gbps** |                               |                             |
| Salsa20            | **2.15 Gbps** | 348 Mbps <br> `6.17x slow`    |                             |
| Salsa20/Poly1305   | **2.03 Gbps** |                               |                             |
| XSalsa20           | **2.01 Gbps** |                               |                             |
| XSalsa20/Poly1305  | **1.9 Gbps**  |                               |                             |
| ChaCha20           | **2 Gbps**    | 353 Mbps <br> `5.68x slow`    |                             |
| ChaCha20/Poly1305  | **1.13 Gbps** | 258 Mbps <br> `4.38x slow`    | 261 Mbps <br> `4.33x slow`  |
| XChaCha20          | **1.88 Gbps** |                               |                             |
| XChaCha20/Poly1305 | **1.09 Gbps** |                               |                             |
| AES-128/CBC        | **1.34 Gbps** | 206 Mbps <br> `6.51x slow`    | 1.02 Gbps <br> `1.31x slow` |
| AES-192/CBC        | **1.17 Gbps** | 180 Mbps <br> `6.49x slow`    | 893 Mbps <br> `1.31x slow`  |
| AES-256/CBC        | **1.03 Gbps** | 160 Mbps <br> `6.41x slow`    | 785 Mbps <br> `1.31x slow`  |
| AES-128/CFB        | **635 Mbps**  | 109 Mbps <br> `5.85x slow`    |                             |
| AES-192/CFB        | **558 Mbps**  | 94.94 Mbps <br> `5.88x slow`  |                             |
| AES-256/CFB        | **498 Mbps**  | 84.55 Mbps <br> `5.89x slow`  |                             |
| AES-128/CTR        | **1.45 Gbps** | 201 Mbps <br> `7.21x slow`    | 594 Mbps <br> `2.44x slow`  |
| AES-192/CTR        | **1.25 Gbps** | 175 Mbps <br> `7.15x slow`    | 556 Mbps <br> `2.25x slow`  |
| AES-256/CTR        | **1.09 Gbps** | 157 Mbps <br> `6.95x slow`    | 517 Mbps <br> `2.12x slow`  |
| AES-128/ECB        | **1.36 Gbps** | 219 Mbps <br> `6.18x slow`    |                             |
| AES-192/ECB        | **1.18 Gbps** | 190 Mbps <br> `6.2x slow`     |                             |
| AES-256/ECB        | **1.04 Gbps** | 168 Mbps <br> `6.17x slow`    |                             |
| AES-128/GCM        | **364 Mbps**  | 15.14 Mbps <br> `24.06x slow` | 248 Mbps <br> `1.47x slow`  |
| AES-192/GCM        | **352 Mbps**  | 14.51 Mbps <br> `24.27x slow` | 242 Mbps <br> `1.45x slow`  |
| AES-256/GCM        | **335 Mbps**  | 14.51 Mbps <br> `23.06x slow` | 227 Mbps <br> `1.47x slow`  |
| AES-128/IGE        | **1.31 Gbps** | 189 Mbps <br> `6.94x slow`    |                             |
| AES-192/IGE        | **1.15 Gbps** | 166 Mbps <br> `6.89x slow`    |                             |
| AES-256/IGE        | **1.01 Gbps** | 150 Mbps <br> `6.71x slow`    |                             |
| AES-128/OFB        | **630 Mbps**  | 115 Mbps <br> `5.48x slow`    |                             |
| AES-192/OFB        | **555 Mbps**  | 99.45 Mbps <br> `5.58x slow`  |                             |
| AES-256/OFB        | **494 Mbps**  | 88.28 Mbps <br> `5.59x slow`  |                             |
| AES-128/PCBC       | **1.35 Gbps** |                               |                             |
| AES-192/PCBC       | **1.18 Gbps** |                               |                             |
| AES-256/PCBC       | **1.04 Gbps** |                               |                             |
| AES-128/XTS        | **1.29 Gbps** |                               |                             |
| AES-192/XTS        | **1.13 Gbps** |                               |                             |
| AES-256/XTS        | **994 Mbps**  |                               |                             |

With 32B message:

| Algorithms         | `cipherlib`    | `PointyCastle`                | `cryptography`               |
| ------------------ | -------------- | ----------------------------- | ---------------------------- |
| XOR                | **7.99 Gbps**  |                               |                              |
| Salsa20            | **1.01 Gbps**  | 135 Mbps <br> `7.49x slow`    |                              |
| Salsa20/Poly1305   | **541 Mbps**   |                               |                              |
| XSalsa20           | **513 Mbps**   |                               |                              |
| XSalsa20/Poly1305  | **352 Mbps**   |                               |                              |
| ChaCha20           | **941 Mbps**   | 135 Mbps <br> `6.95x slow`    |                              |
| ChaCha20/Poly1305  | **322 Mbps**   | 116 Mbps <br> `2.79x slow`    | 67.32 Mbps <br> `4.79x slow` |
| XChaCha20          | **489 Mbps**   |                               |                              |
| XChaCha20/Poly1305 | **243 Mbps**   |                               |                              |
| AES-128/CBC        | **334 Mbps**   | 44.76 Mbps <br> `7.47x slow`  | 107 Mbps <br> `3.13x slow`   |
| AES-192/CBC        | **307 Mbps**   | 39.74 Mbps <br> `7.72x slow`  | 96.84 Mbps <br> `3.17x slow` |
| AES-256/CBC        | **267 Mbps**   | 36.82 Mbps <br> `7.25x slow`  | 87.24 Mbps <br> `3.06x slow` |
| AES-128/CFB        | **416 Mbps**   | 42.35 Mbps <br> `9.83x slow`  |                              |
| AES-192/CFB        | **390 Mbps**   | 36.98 Mbps <br> `10.55x slow` |                              |
| AES-256/CFB        | **334 Mbps**   | 34.58 Mbps <br> `9.67x slow`  |                              |
| AES-128/CTR        | **456 Mbps**   | 48.93 Mbps <br> `9.32x slow`  | 78.98 Mbps <br> `5.77x slow` |
| AES-192/CTR        | **419 Mbps**   | 43.64 Mbps <br> `9.6x slow`   | 79.12 Mbps <br> `5.3x slow`  |
| AES-256/CTR        | **358 Mbps**   | 40.93 Mbps <br> `8.74x slow`  | 75.85 Mbps <br> `4.72x slow` |
| AES-128/ECB        | **356 Mbps**   | 47.47 Mbps <br> `7.5x slow`   |                              |
| AES-192/ECB        | **324 Mbps**   | 41.55 Mbps <br> `7.81x slow`  |                              |
| AES-256/ECB        | **281 Mbps**   | 38.22 Mbps <br> `7.36x slow`  |                              |
| AES-128/GCM        | **64.09 Mbps** | 5.03 Mbps <br> `12.75x slow`  | 50.56 Mbps <br> `1.27x slow` |
| AES-192/GCM        | **62.52 Mbps** | 4.9 Mbps <br> `12.75x slow`   | 48.56 Mbps <br> `1.29x slow` |
| AES-256/GCM        | **60.84 Mbps** | 4.8 Mbps <br> `12.66x slow`   | 45.88 Mbps <br> `1.33x slow` |
| AES-128/IGE        | **363 Mbps**   | 43.78 Mbps <br> `8.3x slow`   |                              |
| AES-192/IGE        | **331 Mbps**   | 38.58 Mbps <br> `8.59x slow`  |                              |
| AES-256/IGE        | **284 Mbps**   | 36.19 Mbps <br> `7.85x slow`  |                              |
| AES-128/OFB        | **428 Mbps**   | 43.09 Mbps <br> `9.94x slow`  |                              |
| AES-192/OFB        | **406 Mbps**   | 37.56 Mbps <br> `10.8x slow`  |                              |
| AES-256/OFB        | **345 Mbps**   | 34.85 Mbps <br> `9.91x slow`  |                              |
| AES-128/PCBC       | **386 Mbps**   |                               |                              |
| AES-192/PCBC       | **354 Mbps**   |                               |                              |
| AES-256/PCBC       | **300 Mbps**   |                               |                              |
| AES-128/XTS        | **329 Mbps**   |                               |                              |
| AES-192/XTS        | **306 Mbps**   |                               |                              |
| AES-256/XTS        | **254 Mbps**   |                               |                              |

> All benchmarks are done on 36GB _Apple M3 Pro_ using compiled _exe_
>
> Dart SDK version: 3.8.1 (stable) (Wed May 28 00:47:25 2025 -0700) on "macos_arm64"

<!-- file: BENCHMARK.md -->
