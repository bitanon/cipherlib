# cipherlib

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
import 'package:hashlib_codecs/hashlib_codecs.dart';

void main() {
  var key = [0x54];
  var inp = [0x03, 0xF1];
  print('text: ${toBinary(inp)}');
  print(' key: ${toBinary(key)}');
  print(' XOR: ${toBinary(xor(inp, key))}');
}
```
