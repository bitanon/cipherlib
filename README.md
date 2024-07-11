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

| Ciphers           | Public class and methods                                         |    Source     |
| ----------------- | ---------------------------------------------------------------- | :-----------: |
| AES               | `AES`,                                                           | NIST.FIPS.197 |
| XOR               | `XOR`, `xor`, `xorStream`                                        |   Wikipedia   |
| ChaCha20          | `ChaCha20`, `chacha20`, `chacha20Stream`                         |   RFC-8439    |
| ChaCha20/Poly1305 | `ChaCha20Poly1305`, `chacha20poly1305`, `chacha20poly1305Stream` |   RFC-8439    |
| Salsa20           | `Salsa20`, `salsa20`, `salsa20Stream`                            | Snuffle-2005  |
| Salsa20/Poly1305  | `Salsa20Poly1305`, `salsa20poly1305`, `salsa20poly1305Stream`    | Snuffle-2005  |

Available modes for AES:

- `ECB` : Electronic Codeblock
- `CBC` : Cipher Block Chaining
- `CTR` : Counter
- `GCM` : Galois/Counter Mode
- `CFB` : Cipher Feedback
- `OFB` : Output Feedback
- `PCBC` : Propagating Cipher Block Chaining

## Getting started

The following import will give you access to all of the algorithms in this package.

```dart
import 'package:cipherlib/cipherlib.dart';
```

Check the [API Reference](https://pub.dev/documentation/cipherlib/latest/cipherlib/cipherlib-library.html) for details.

## Usage

Examples can be found inside the `example` folder.

```dart
import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';

void main() {
  print('----- AES -----');
  {
    var plain = 'A not very secret message';
    var key = 'abcdefghijklmnop'.codeUnits;
    var iv = 'lka9JLKasljkdPsd'.codeUnits;
    print('  Text: $plain');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(iv)}');
    print('  ECB: ${toHex(AES(key).ecb().encryptString(plain))}');
    print('  CBC: ${toHex(AES(key).cbc(iv).encryptString(plain))}');
    print('  CTR: ${toHex(AES(key).ctr(iv).encryptString(plain))}');
    print('  GCM: ${toHex(AES(key).gcm(iv).encryptString(plain))}');
    print('  CFB: ${toHex(AES(key).cfb(iv).encryptString(plain))}');
    print('  OFB: ${toHex(AES(key).ofb(iv).encryptString(plain))}');
    print(' PCBC: ${toHex(AES(key).pcbc(iv).encryptString(plain))}');
  }
  print('');

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
  print('');

  print('----- ChaCha20 -----');
  {
    var text = "Hide me!";
    var key = fromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    var nonce = fromHex("00000000000000004a000000");
    var res = chacha20poly1305(toUtf8(text), key, nonce: nonce);
    var plain = chacha20(res.message, key, nonce: nonce);
    print('  Text: $text');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(nonce)}');
    print('Cipher: ${toHex(res.message)}');
    print('   Tag: ${res.mac.hex()}');
    print(' Plain: ${fromUtf8(plain)}');
  }
  print('');

  print('----- Salsa20 -----');
  {
    var text = "Hide me!";
    var key = fromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    var nonce = fromHex("00000000000000004a00000000000000");
    var res = salsa20poly1305(toUtf8(text), key, nonce: nonce);
    var plain = salsa20(res.message, key, nonce: nonce);
    print('  Text: $text');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(nonce)}');
    print('Cipher: ${toHex(res.message)}');
    print('   Tag: ${res.mac.hex()}');
    print(' Plain: ${fromUtf8(plain)}');
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
| XOR                       | **241MB/s**    | ➖                           | ➖                           |
| ChaCha20                  | **107.60MB/s** | 30.48MB/s <br> `253% slower` | ➖                           |
| ChaCha20/Poly1305         | **75.32MB/s**  | ➖                           | 33.24MB/s <br> `127% slower` |
| ChaCha20/Poly1305(digest) | **247.47MB/s** | ➖                           | ➖                           |
| Salsa20                   | **107.24MB/s** | 27.91MB/s <br> `284% slower` | ➖                           |
| Salsa20/Poly1305          | **76.42MB/s**  | ➖                           | ➖                           |
| Salsa20/Poly1305(digest)  | **248.50MB/s** | ➖                           | ➖                           |

With 1KB message (5000 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`               | `cryptography`               |
| ------------------------- | -------------- | ---------------------------- | ---------------------------- |
| XOR                       | **250.20MB/s** | ➖                           | ➖                           |
| ChaCha20                  | **108.38MB/s** | 30.87MB/s <br> `251% slower` | ➖                           |
| ChaCha20/Poly1305         | **71.48MB/s**  | ➖                           | 31.39MB/s <br> `128% slower` |
| ChaCha20/Poly1305(digest) | **213.58MB/s** | ➖                           | ➖                           |
| Salsa20                   | **108.21MB/s** | 29.29MB/s <br> `269% slower` | ➖                           |
| Salsa20/Poly1305          | **72.17MB/s**  | ➖                           | ➖                           |
| Salsa20/Poly1305(digest)  | **217.38MB/s** | ➖                           | ➖                           |

With 10B message (100000 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`              | `cryptography`              |
| ------------------------- | -------------- | --------------------------- | --------------------------- |
| XOR                       | **185.62MB/s** | ➖                          | ➖                          |
| ChaCha20                  | **32.03MB/s**  | 3.91MB/s <br> `719% slower` | ➖                          |
| ChaCha20/Poly1305         | **9.71MB/s**   | ➖                          | 4.14MB/s <br> `134% slower` |
| ChaCha20/Poly1305(digest) | **14.31MB/s**  | ➖                          | ➖                          |
| Salsa20                   | **32.33MB/s**  | 3.81MB/s <br> `748% slower` | ➖                          |
| Salsa20/Poly1305          | **9.81MB/s**   | ➖                          | ➖                          |
| Salsa20/Poly1305(digest)  | **14.25MB/s**  | ➖                          | ➖                          |

> All benchmarks are done on _AMD Ryzen 7 5800X_ processor and _3200MHz_ RAM using compiled _exe_
>
> Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
