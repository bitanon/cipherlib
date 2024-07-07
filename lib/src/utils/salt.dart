// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart';

/// Random initialization vector builder.
class Salt {
  final Uint8List bytes;

  const Salt(this.bytes);

  /// Create a random salt value
  factory Salt.random(int size) => Salt(randomBytes(size));

  /// Create a salt value from a list of bytes
  factory Salt.bytes(List<int> data) =>
      Salt(data is Uint8List ? data : Uint8List.fromList(data));
}

/// The 64-bit initialization vector builder.
///
/// Common usage: AES cipher in CTR mode.
class Salt64 {
  final Uint8List bytes;

  /// Create a 64-bit value from bytes only
  const Salt64(this.bytes);

  /// Create a random 64-bit value
  factory Salt64.random() => Salt64(randomBytes(8));

  /// Create a 64-bit value from 64-bit integer
  factory Salt64.int64(int value) => Salt64(Uint8List.fromList([
        value >>> 56,
        value >>> 48,
        value >>> 40,
        value >>> 32,
        value >>> 24,
        value >>> 16,
        value >>> 8,
        value,
      ]));

  /// Create a 64-bit value from two 32-bit integers
  factory Salt64.int32(int high, int low) => Salt64(Uint8List.fromList([
        high >>> 24,
        high >>> 16,
        high >>> 8,
        high,
        low >>> 24,
        low >>> 16,
        low >>> 8,
        low,
      ]));

  /// Create a 64-bit value from a list of bytes
  factory Salt64.bytes(List<int> data) =>
      Salt64(data is Uint8List ? data : Uint8List.fromList(data));

  int asInt64() =>
      (bytes[0] << 56) |
      (bytes[1] << 48) |
      (bytes[2] << 40) |
      (bytes[3] << 32) |
      (bytes[4] << 24) |
      (bytes[5] << 16) |
      (bytes[6] << 8) |
      (bytes[7]);

  List<int> asInt32() => [
        (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | (bytes[3]),
        (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | (bytes[7]),
      ];
}
