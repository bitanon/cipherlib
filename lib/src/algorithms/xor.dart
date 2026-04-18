// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import '../core/cipher.dart';
import '../utils/typed_data.dart';

/// XOR (exclusive or) cipher is a simple and lightweight method of encrypting
/// data. It is often used for basic data obfuscation.
///
/// **WARNING**: This cipher is not intended to be used for security purposes.
///
/// This implementation is based on [XOR cipher][wiki] from Wikipedia.
///
/// [wiki]: https://en.wikipedia.org/wiki/XOR_cipher
class XOR extends Cipher {
  @override
  final String name = "XOR";

  /// Key for the cipher
  final Uint8List key;

  const XOR._(this.key);

  /// Creates a [XOR] with `List<int>` [key], transforming every elements to
  /// unsigned 8-bit numbers.
  factory XOR(List<int> key) => XOR._(toUint8List(key));

  @override
  Uint8List convert(List<int> message) {
    if (key.isEmpty && message.isNotEmpty) {
      throw ArgumentError.value(key, 'key', 'must not be empty');
    }
    final output = Uint8List(message.length);
    for (int i = 0, k = 0; i < output.length; ++i, ++k) {
      if (k == key.length) {
        k = 0;
      }
      output[i] = message[i] ^ key[k];
    }
    return output;
  }
}
