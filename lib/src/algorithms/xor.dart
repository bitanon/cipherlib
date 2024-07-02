// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';

/// This sink is used by the [XOR] algorithm.
class XORSink extends CipherSink {
  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;
  late final int _maxPos = _key.length - 1;

  XORSink(this._key) {
    if (_key.isEmpty) {
      throw ArgumentError('The key is empty');
    }
  }

  @override
  Uint8List add(List<int> data, [bool last = false]) {
    if (_closed) {
      throw StateError('The sink is closed');
    }
    _closed = last;
    var result = Uint8List.fromList(data);
    for (int i = 0; i < result.length; i++) {
      result[i] ^= _key[_pos];
      _pos = _pos == _maxPos ? 0 : _pos + 1;
    }
    return result;
  }
}

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

  const XOR(this.key);

  /// Creates a [XOR] with List<int> [key], transforming every elements to
  /// unsigned 8-bit numbers.
  factory XOR.fromList(List<int> key) =>
      XOR(key is Uint8List ? key : Uint8List.fromList(key));

  @override
  @pragma('vm:prefer-inline')
  XORSink createSink() => XORSink(key);

  @override
  Uint8List convert(List<int> message) {
    var result = Uint8List.fromList(message);
    for (int i = 0, j = 0; i < message.length; ++i) {
      result[i] ^= key[j++];
      if (j == key.length) {
        j = 0;
      }
    }
    return result;
  }
}
