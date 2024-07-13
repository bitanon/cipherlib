// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';

/// Random initialization vector builder.
class Nonce {
  /// The list of bytes representing this Nonce
  final Uint8List bytes;

  const Nonce(this.bytes);

  /// Create a nonce with zeros
  factory Nonce.zero(int size) => Nonce(Uint8List(0));

  /// Create a random salt value
  factory Nonce.random(int size) => Nonce(randomBytes(size));

  /// Create a nonce from a list of bytes
  factory Nonce.hex(String data) => Nonce(fromHex(data));

  /// Create a nonce from a list of bytes
  factory Nonce.bytes(List<int> data) =>
      Nonce(data is Uint8List ? data : Uint8List.fromList(data));

  /// Gets the bytes as Base-16 character sequence
  String hex({bool upper = false}) => toHex(bytes, upper: upper);
}

/// The 64-bit initialization vector builder.
class Nonce64 extends Nonce {
  /// Create a 64-bit nonce from bytes only
  const Nonce64._(Uint8List bytes) : super(bytes);

  /// Create a 64-bit nonce with zeros
  factory Nonce64.zero() => Nonce64._(Uint8List(8));

  /// Create a random 64-bit nonce
  factory Nonce64.random() => Nonce64._(randomBytes(8));

  /// Create a 64-bit nonce from a list of bytes
  factory Nonce64.bytes(List<int> data) {
    int j = data.length - 1;
    if (j > 7) j = 7;
    var bytes = Uint8List(8);
    for (int i = 7; i >= 0 && j >= 0; i--, j--) {
      bytes[i] = data[j];
    }
    return Nonce64._(bytes);
  }

  /// Create a 64-bit nonce from a Base-16 string sequence
  factory Nonce64.hex(String data) => Nonce64.bytes(fromHex(data));

  /// Create 64-bit nonce from a 64-bit integer in big-endian order
  factory Nonce64.from64(int value) => Nonce64._(
        Uint8List.fromList([
          value >>> 56,
          value >>> 48,
          value >>> 40,
          value >>> 32,
          value >>> 24,
          value >>> 16,
          value >>> 8,
          value,
        ]),
      );

  /// Create 64-bit nonce from two 32-bit integers in big-endian order
  factory Nonce64.from32(int high, int low) => Nonce64._(
        Uint8List.fromList([
          high >>> 24,
          high >>> 16,
          high >>> 8,
          high,
          low >>> 24,
          low >>> 16,
          low >>> 8,
          low,
        ]),
      );
}
