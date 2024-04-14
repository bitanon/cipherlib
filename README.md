# cipherlib

[![plugin version](https://img.shields.io/pub/v/cipherlib?label=pub)](https://pub.dev/packages/cipherlib)
[![dependencies](https://img.shields.io/badge/dependencies-zero-889)](https://github.com/bitanon/cipherlib/blob/master/pubspec.yaml)
[![dart support](https://img.shields.io/badge/dart-%3e%3d%202.14.0-39f?logo=dart)](https://dart.dev/guides/whats-new#september-8-2021-214-release)
[![likes](https://img.shields.io/pub/likes/cipherlib?logo=dart)](https://pub.dev/packages/cipherlib/score)
[![pub points](https://img.shields.io/pub/points/cipherlib?logo=dart&color=teal)](https://pub.dev/packages/cipherlib/score)
[![popularity](https://img.shields.io/pub/popularity/cipherlib?logo=dart)](https://pub.dev/packages/cipherlib/score)

Implementations of cryptographic algorithms for encryption and decryption in Dart.

## Features

| Ciphers  | Public class and methods               |  Source   |
| -------- | -------------------------------------- | :-------: |
| ChaCha20 | `ChaCha20`, `chacha20`, `chacha20Pipe` | RFC-8439  |
| XOR      | `XOR`, `xor`, `xorPipe`                | Wikipedia |

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
    var cipher = chacha20(utf8.encode(text), key, nonce);
    var plain = chacha20(cipher, key, nonce);
    print('  Text: $text');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(nonce)}');
    print('Cipher: ${toHex(cipher)}');
    print(' Plain: ${utf8.decode(plain)}');
  }
}
```

# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib

With 5MB message (10 iterations):

| Algorithms     | `cipherlib`    |
| -------------- | -------------- |
| XOR            | **243.84MB/s** |
| XOR(pipe)      | **66.57TB/s**  |
| ChaCha20       | **125.40MB/s** |
| ChaCha20(pipe) | **58.43TB/s**  |

With 1KB message (5000 iterations):

| Algorithms     | `cipherlib`    |
| -------------- | -------------- |
| XOR            | **266.28MB/s** |
| XOR(pipe)      | **13.71GB/s**  |
| ChaCha20       | **129.03MB/s** |
| ChaCha20(pipe) | **11.86GB/s**  |

With 10B message (100000 iterations):

| Algorithms     | `cipherlib`    |
| -------------- | -------------- |
| XOR            | **190.05MB/s** |
| XOR(pipe)      | **136.98MB/s** |
| ChaCha20       | **31.78MB/s**  |
| ChaCha20(pipe) | **118.66MB/s** |

> All benchmarks are done on _AMD Ryzen 7 5800X_ processor and _3200MHz_ RAM using compiled _exe_
>
> Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
