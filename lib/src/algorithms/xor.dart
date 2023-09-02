// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';

/// XOR (exclusive or) cipher is a simple and lightweight method of encrypting
/// data. It is often used for basic data obfuscation.
///
/// **WARNING**: This cipher is not intended to be used for secure purposes.
class XOR extends SymmetricCipher {
  final Uint8List key;

  /// Create a new instance for XOR Encryption
  const XOR._(this.key);

  factory XOR(List<int> key) {
    if (key.isEmpty) {
      throw ArgumentError('The key must not be empty');
    }
    if (key is Uint8List) {
      return XOR._(key);
    } else {
      return XOR._(Uint8List.fromList(key));
    }
  }

  @override
  Uint8List convert(List<int> message) {
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
  Stream<int> pipe(Stream<int> stream) async* {
    int i = 0;
    await for (var x in stream) {
      yield x ^ key[i++];
      if (i == key.length) {
        i = 0;
      }
    }
  }
}
