# cipherlib

[![plugin version](https://img.shields.io/pub/v/cipherlib?label=pub)](https://pub.dev/packages/cipherlib)
[![dependencies](https://img.shields.io/badge/dependencies-zero-889)](https://github.com/bitanon/cipherlib/blob/master/pubspec.yaml)
[![dart support](https://img.shields.io/badge/dart-%3e%3d%202.14.0-39f?logo=dart)](https://dart.dev/guides/whats-new#september-8-2021-214-release)
[![likes](https://img.shields.io/pub/likes/cipherlib?logo=dart)](https://pub.dev/packages/cipherlib/score)
[![pub points](https://img.shields.io/pub/points/cipherlib?logo=dart&color=teal)](https://pub.dev/packages/cipherlib/score)
[![popularity](https://img.shields.io/pub/popularity/cipherlib?logo=dart)](https://pub.dev/packages/cipherlib/score)

Implementations of cryptographic algorithms for encryption and decryption in Dart.

## Features

| Ciphers | Available methods       |  Source   |
| ------- | ----------------------- | :-------: |
| XOR     | `XOR`, `xor`, `xorPipe` | Wikipedia |

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
import 'package:cipherlib/cipherlib.dart';

void main() {
  var key = [0x54];
  var inp = [0x03, 0xF1];
  print('text: ${toBinary(inp)}');
  print(' key: ${toBinary(key)}');
  print(' XOR: ${toBinary(xor(inp, key))}');
}
```

# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib

With 5MB message (10 iterations):

| Algorithms | `cipherlib[key:10B]` | `cipherlib[key:1KB]` | `cipherlib[key:5MB]` |
| ---------- | -------------------- | -------------------- | -------------------- |
| XOR        | **246.28MB/s**       | 245.36MB/s           | 245.48MB/s           |
| XOR(pipe)  | 70.81TB/s            | **70.98TB/s**        | 70.84TB/s            |

With 1KB message (5000 iterations):

| Algorithms | `cipherlib[key:10B]` | `cipherlib[key:1KB]` | `cipherlib[key:5MB]`           |
| ---------- | -------------------- | -------------------- | ------------------------------ |
| XOR        | 256.42MB/s           | 256.41MB/s           | **256.65MB/s**                 |
| XOR(pipe)  | 14.34GB/s            | 14.38GB/s            | **14.44GB/s** <br> `1% faster` |

With 10B message (100000 iterations):

| Algorithms | `cipherlib[key:10B]` | `cipherlib[key:1KB]`            | `cipherlib[key:5MB]`        |
| ---------- | -------------------- | ------------------------------- | --------------------------- |
| XOR        | 185.24MB/s           | **186.45MB/s** <br> `1% faster` | 186.28MB/s <br> `1% faster` |
| XOR(pipe)  | **144.20MB/s**       | 143.58MB/s                      | 141.57MB/s <br> `2% slower` |

> All benchmarks are done on _AMD Ryzen 7 5800X_ processor and _3200MHz_ RAM using compiled _exe_
>
> Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
