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
class XOR extends StreamCipher {
  @override
  final String name = "XOR";

  /// Key for the cipher
  final Uint8List key;

  const XOR._(this.key);

  /// Creates a [XOR] with `List<int>` [key], transforming every elements to
  /// unsigned 8-bit numbers.
  factory XOR(List<int> key) {
    if (key.isEmpty) {
      throw ArgumentError.value(key, 'key', 'must not be empty');
    }
    return XOR._(toUint8List(key));
  }

  @override
  Uint8List convert(List<int> message) {
    int kLen = key.length;
    int mLen = message.length;
    final output = Uint8List(mLen);
    for (int i = 0, k = 0; i < mLen; ++i, ++k) {
      if (k == kLen) {
        k = 0;
      }
      output[i] = message[i] ^ key[k];
    }
    return output;
  }

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) async* {
    int k = 0;
    int kLen = key.length;
    await for (final chunk in stream) {
      int mLen = chunk.length;
      final output = Uint8List(mLen);
      for (int i = 0; i < mLen; ++i, ++k) {
        if (k == kLen) {
          k = 0;
        }
        output[i] = chunk[i] ^ key[k];
      }
      yield output;
    }
  }
}
