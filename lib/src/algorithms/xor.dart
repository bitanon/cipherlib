// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';
import 'package:cipherlib/src/core/cipher_sink.dart';

/// This sink is used by the [XOR] algorithm.
class XORSink implements CipherSink {
  XORSink(this._key) {
    if (_key.isEmpty) {
      throw ArgumentError('The key must not be empty');
    }
  }

  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;

  @override
  bool get closed => _closed;

  @override
  void reset() {
    _pos = 0;
    _closed = false;
  }

  @override
  Uint8List add(
    List<int> data, [
    bool last = false,
    int start = 0,
    int? end,
  ]) {
    if (_closed) {
      throw StateError('The sink is closed');
    }
    _closed = last;
    end ??= data.length;

    var result = Uint8List(end - start);
    for (int i = start; i < end; i++) {
      if (_pos == _key.length) {
        _pos = 0;
      }
      result[i] = data[i] ^ _key[_pos++];
    }
    return result;
  }

  @override
  Uint8List close() {
    _closed = true;
    return Uint8List(0);
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
}
