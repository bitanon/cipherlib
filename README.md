# cipherlib

[![plugin version](https://img.shields.io/pub/v/cipherlib?label=pub)](https://pub.dev/packages/cipherlib)
[![dart support](https://img.shields.io/badge/dart-%3e%3d%202.14.0-39f?logo=dart)](https://dart.dev/guides/whats-new#september-8-2021-214-release)
[![likes](https://img.shields.io/pub/likes/cipherlib?logo=dart)](https://pub.dev/packages/cipherlib/score)
[![pub points](https://img.shields.io/pub/points/cipherlib?logo=dart&color=teal)](https://pub.dev/packages/cipherlib/score)
[![popularity](https://img.shields.io/pub/popularity/cipherlib?logo=dart)](https://pub.dev/packages/cipherlib/score)

Implementations of cryptographic algorithms for encryption and decryption in Dart.

## Depencencies

There are only 2 dependencies used by this package:

- [hashlib](https://pub.dev/packages/hashlib)
- [hashlib_codecs](https://pub.dev/packages/hashlib_codecs)

## Features

| Ciphers           | Public class and methods                                                                                             |    Source    |
| ----------------- | -------------------------------------------------------------------------------------------------------------------- | :----------: |
| XOR               | `XOR`, `xor`, `xorStream`                                                                                            |  Wikipedia   |
| ChaCha20          | `ChaCha20`, `chacha20`, `chacha20Stream`                                                                             |   RFC-8439   |
| ChaCha20/Poly1305 | `ChaCha20Poly1305`, `chacha20poly1305Digest`, `chacha20poly1305Verify`, `chacha20poly1305`, `chacha20poly1305Stream` |   RFC-8439   |
| Salsa20           | `Salsa20`, `salsa20`, `salsa20Stream`                                                                                | Snuffle-2005 |
| Salsa20/Poly1305  | `Salsa20Poly1305`, `salsa20poly1305Digest`, `salsa20poly1305Verify`, `salsa20poly1305`, `salsa20poly1305Stream`      | Snuffle-2005 |

## Getting started

The following import will give you access to all of the algorithms in this package.

```dart
import 'package:cipherlib/cipherlib.dart';
```

Check the [API Reference](https://pub.dev/documentation/cipherlib/latest/cipherlib/cipherlib-library.html) for details.

## Usage

Examples can be found inside the `example` folder.

```dart
import 'dart:convert';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';

void main() {
  print('----- XOR -----');
  {
    var key = [0x54];
    var inp = [0x03, 0xF1];
    var cipher = xor(inp, key);
    var plain = xor(cipher, key);
    print('  Text: ${toBinary(inp)}');
    print('   Key: ${toBinary(key)}');
    print('   XOR: ${toBinary(cipher)}');
    print(' Plain: ${toBinary(plain)}');
  }

  print('----- ChaCha20 -----');
  {
    var text = "Hide me!";
    var key = fromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    var nonce = fromHex("000000000000004a00000000");
    var result = chacha20poly1305(utf8.encode(text), key, nonce: nonce);
    var plain = chacha20poly1305(
      result.cipher,
      key,
      nonce: nonce,
      tag: result.tag.bytes,
    );
    print('  Text: $text');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(nonce)}');
    print('Cipher: ${toHex(result.cipher)}');
    print('   Tag: ${result.tag.hex()}');
    print(' Plain: ${utf8.decode(plain.cipher)}');
  }
}
```

# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib
- **PointyCastle** : https://pub.dev/packages/pointycastle
- **Cryptography** : https://pub.dev/packages/cryptography

With 5MB message (10 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`               | `cryptography`               |
| ------------------------- | -------------- | ---------------------------- | ---------------------------- |
| XOR                       | **259.18MB/s** | ➖                           | ➖                           |
| ChaCha20                  | **111.43MB/s** | 32.80MB/s <br> `240% slower` | ➖                           |
| ChaCha20/Poly1305         | **111.40MB/s** | ➖                           | 33.40MB/s <br> `234% slower` |
| ChaCha20/Poly1305(digest) | **264.11MB/s** | ➖                           | ➖                           |
| Salsa20                   | **110.24MB/s** | 30.05MB/s <br> `267% slower` | ➖                           |
| Salsa20/Poly1305          | **110.32MB/s** | ➖                           | ➖                           |
| Salsa20/Poly1305(digest)  | **257.01MB/s** | ➖                           | ➖                           |

With 1KB message (5000 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`               | `cryptography`               |
| ------------------------- | -------------- | ---------------------------- | ---------------------------- |
| XOR                       | **271.84MB/s** | ➖                           | ➖                           |
| ChaCha20                  | **110.43MB/s** | 31.77MB/s <br> `248% slower` | ➖                           |
| ChaCha20/Poly1305         | **110.04MB/s** | ➖                           | 31.16MB/s <br> `253% slower` |
| ChaCha20/Poly1305(digest) | **227.55MB/s** | ➖                           | ➖                           |
| Salsa20                   | **111.28MB/s** | 29.29MB/s <br> `280% slower` | ➖                           |
| Salsa20/Poly1305          | **110.90MB/s** | ➖                           | ➖                           |
| Salsa20/Poly1305(digest)  | **227.78MB/s** | ➖                           | ➖                           |

With 10B message (100000 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`              | `cryptography`              |
| ------------------------- | -------------- | --------------------------- | --------------------------- |
| XOR                       | **197.94MB/s** | ➖                          | ➖                          |
| ChaCha20                  | **31.49MB/s**  | 4.05MB/s <br> `676% slower` | ➖                          |
| ChaCha20/Poly1305         | **31.73MB/s**  | ➖                          | 4.05MB/s <br> `682% slower` |
| ChaCha20/Poly1305(digest) | **14.46MB/s**  | ➖                          | ➖                          |
| Salsa20                   | **31.76MB/s**  | 3.79MB/s <br> `737% slower` | ➖                          |
| Salsa20/Poly1305          | **32.38MB/s**  | ➖                          | ➖                          |
| Salsa20/Poly1305(digest)  | **14.47MB/s**  | ➖                          | ➖                          |

> All benchmarks are done on _AMD Ryzen 7 5800X_ processor and _3200MHz_ RAM using compiled _exe_
>
> Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
