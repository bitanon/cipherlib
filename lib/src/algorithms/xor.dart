// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/stream_cipher.dart';

/// XOR (exclusive or) cipher is a simple and lightweight method of encrypting
/// data. It is often used for basic data obfuscation.
///
/// **WARNING**: This cipher is not intended to be used for security purposes.
///
/// This implementation is based on [XOR cipher][xor_wiki] from Wikipedia.
///
/// [xor_wiki]: https://en.wikipedia.org/wiki/XOR_cipher
class XOR implements StreamCipher {
  @override
  final String name = "XOR";

  /// Key for the cipher
  final List<int> key;

  const XOR(this.key);

  @override
  Uint8List convert(List<int> message) {
    if (key.isEmpty) {
      throw ArgumentError('The key must not be empty');
    }
    int i, j = 0;
    var result = Uint8List.fromList(message);
    for (i = 0; i < message.length; ++i) {
      result[i] ^= key[j++];
      if (j == key.length) {
        j = 0;
      }
    }
    return result;
  }

  @override
  Stream<int> stream(Stream<int> stream) async* {
    if (key.isEmpty) {
      throw ArgumentError('The key must not be empty');
    }
    int i = 0;
    await for (var x in stream) {
      yield (x ^ key[i++]) & 0xFF;
      if (i == key.length) {
        i = 0;
      }
    }
  }
}
