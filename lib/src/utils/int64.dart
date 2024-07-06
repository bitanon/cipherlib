// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart';

/// The 64-bit number builder.
///
/// It is used by AES cipher in CTR mode.
class Int64 {
  final Uint8List bytes;

  /// Create a 64-bit value from bytes only
  const Int64(this.bytes);

  /// Create a 64-bit value from 64-bit integer
  factory Int64.int64(int value) => Int64(Uint8List.fromList([
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
  factory Int64.int32(int high, int low) => Int64(Uint8List.fromList([
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
  factory Int64.bytes(List<int> data) =>
      Int64(data is Uint8List ? data : Uint8List.fromList(data));

  /// Create a random 64-bit value
  factory Int64.random() => Int64(randomBytes(8));
}
