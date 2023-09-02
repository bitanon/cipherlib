# cipherlib

[![plugin version](https://img.shields.io/pub/v/cipherlib?label=pub)](https://pub.dev/packages/cipherlib)
[![dependencies](https://img.shields.io/badge/dependencies-zero-889)](https://github.com/bitanon/cipherlib/blob/master/pubspec.yaml)
[![dart support](https://img.shields.io/badge/dart-%3e%3d%202.14.0-39f?logo=dart)](https://dart.dev/guides/whats-new#september-8-2021-214-release)
[![likes](https://img.shields.io/pub/likes/cipherlib?logo=dart)](https://pub.dev/packages/cipherlib/score)
[![pub points](https://img.shields.io/pub/points/cipherlib?logo=dart&color=teal)](https://pub.dev/packages/cipherlib/score)
[![popularity](https://img.shields.io/pub/popularity/cipherlib?logo=dart)](https://pub.dev/packages/cipherlib/score)

Implementations of cryptographic algorithms for encryption and decryption in Dart.

## Features

| Ciphers | Available methods |  Source   |
| ------- | ----------------- | :-------: |
| XOR     | `XOR`, `xor`      | Wikipedia |

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
