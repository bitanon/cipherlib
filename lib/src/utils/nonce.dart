// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show randomBytes;
import 'package:hashlib_codecs/hashlib_codecs.dart' show fromHex;

Uint8List _copyBytes(int size, List<int> data) {
  int n = data.length;
  if (n == size) {
    if (data is Uint8List) {
      return data;
    }
    return Uint8List.fromList(data);
  }
  if (n > size) {
    n = size;
  }
  var bytes = Uint8List(size);
  for (int i = 0; i < n; i++) {
    bytes[i] = data[i];
  }
  return bytes;
}

Uint8List _reverseBytes(List<int> data) {
  int n = data.length;
  var bytes = Uint8List(n);
  for (int i = 0, j = n - 1; i < n; i++, j--) {
    bytes[i] = data[j];
  }
  return bytes;
}

abstract class _NonceBase {
  const _NonceBase();

  /// The list of bytes representing this Nonce
  Uint8List get bytes;

  /// Gets a nonce with reverse order of the underlying bytes
  _NonceBase reverse();

  @override
  int get hashCode => bytes.hashCode;

  @override
  bool operator ==(other) {
    if (other is! Nonce) {
      return false;
    }
    return other.bytes == bytes;
  }
}

/// Random initialization vector builder.
class Nonce extends _NonceBase {
  @override
  final Uint8List bytes;

  const Nonce._(this.bytes);

  /// Get the size of this nonce
  int get size => bytes.length;

  /// Get the size of this nonce in bits
  int get sizeInBits => bytes.length << 3;

  /// Create a nonce with zeros
  factory Nonce.zero(int size) => Nonce._(Uint8List(size));

  /// Create a random salt value
  factory Nonce.random(int size) => Nonce._(randomBytes(size));

  /// Create a nonce from a list of bytes
  factory Nonce.bytes(List<int> data, [int? size]) =>
      Nonce._(_copyBytes(size ?? data.length, data));

  /// Create a nonce from a Base-16 encoded string
  factory Nonce.hex(String data, [int? size]) =>
      Nonce.bytes(fromHex(data), size);

  @override
  Nonce reverse() => Nonce._(_reverseBytes(bytes));

  /// Adds [padLength] bytes at the start filled with zeros, and returns a new
  /// [Nonce].
  Nonce padLeft(int padLength) {
    int i;
    var result = Uint8List(size + padLength);
    for (i = 0; i < size; i++) {
      result[i + padLength] = bytes[i];
    }
    return Nonce.bytes(result);
  }

  /// Adds [padLength] bytes at the end filled with zeros, and returns a new
  /// [Nonce].
  Nonce padRight(int padLength) {
    int i;
    var result = Uint8List(size + padLength);
    for (i = 0; i < size; i++) {
      result[i] = bytes[i];
    }
    return Nonce.bytes(result);
  }
}

/// The 64-bit initialization vector builder.
class Nonce64 extends Nonce {
  const Nonce64._(Uint8List bytes) : super._(bytes);

  /// Create a 64-bit nonce with zeros
  factory Nonce64.zero() => Nonce64._(Uint8List(8));

  /// Create a random 64-bit nonce
  factory Nonce64.random() => Nonce64._(randomBytes(8));

  /// Create a 64-bit nonce from a list of bytes
  factory Nonce64.bytes(List<int> data) => Nonce64._(_copyBytes(8, data));

  /// Create a 64-bit nonce from a Base-16 string sequence
  factory Nonce64.hex(String data) => Nonce64.bytes(fromHex(data));

  /// Create 64-bit nonce from a 64-bit integer in little-endian order
  ///
  /// To get it in big-endian order use the [reverse] method.
  factory Nonce64.int64(int value) => Nonce64._(
        Uint8List.fromList([
          value,
          value >>> 8,
          value >>> 16,
          value >>> 24,
          value >>> 32,
          value >>> 40,
          value >>> 48,
          value >>> 56,
        ]),
      );

  /// Create 64-bit nonce from two 32-bit integers in little-endian order.
  ///
  /// Parameters:
  /// - [low] is the least-significant 32-bit bytes
  /// - [high] is the most-significant 32-bit bytes
  ///
  /// Example:
  /// ```
  /// 64-bit number: 0x0102030405060708
  ///   32-bit high: 0x01020304
  ///   32-bit  low: 0x05060708
  /// ```
  ///
  /// To get it in big-endian order use the [reverse] method.
  factory Nonce64.int32(int low, [int high = 0]) => Nonce64._(
        Uint8List.fromList([
          low,
          low >>> 8,
          low >>> 16,
          low >>> 24,
          high,
          high >>> 8,
          high >>> 16,
          high >>> 24,
        ]),
      );

  @override
  Nonce64 reverse() => Nonce64._(_reverseBytes(bytes));
}

/// The 128-bit initialization vector builder.
class Nonce128 extends Nonce {
  const Nonce128._(Uint8List bytes) : super._(bytes);

  /// Create a 128-bit nonce with zeros
  factory Nonce128.zero() => Nonce128._(Uint8List(16));

  /// Create a random 128-bit nonce
  factory Nonce128.random() => Nonce128._(randomBytes(16));

  /// Create a 128-bit nonce from a list of bytes
  factory Nonce128.bytes(List<int> data) => Nonce128._(_copyBytes(16, data));

  /// Create a 128-bit nonce from a Base-16 string sequence
  factory Nonce128.hex(String data) => Nonce128.bytes(fromHex(data));

  /// Create 128-bit nonce from two 64-bit integers in little-endian order.
  ///
  /// Parameters:
  /// - [low] is the least-significant 64-bit bytes
  /// - [high] is the most-significant 64-bit bytes
  ///
  /// Example:
  /// ```
  /// 128-bit number: 0x0102030405060708090A0B0C0D0E0F10
  ///    64-bit high: 0x0102030405060708
  ///    64-bit  low: 0x090A0B0C0D0E0F10
  /// ```
  ///
  /// To get it in big-endian order use the [reverse] method.
  factory Nonce128.int64(int low, [int high = 0]) => Nonce128._(
        Uint8List.fromList([
          low,
          low >>> 8,
          low >>> 16,
          low >>> 24,
          low >>> 32,
          low >>> 40,
          low >>> 48,
          low >>> 56,
          high,
          high >>> 8,
          high >>> 16,
          high >>> 24,
          high >>> 32,
          high >>> 40,
          high >>> 48,
          high >>> 56,
        ]),
      );

  /// Create 128-bit nonce from four 32-bit integers in little-endian order.
  ///
  ///
  /// Parameters:
  /// - [ll] is the least-significant 32-bit bytes
  /// - [lh] is the second least-significant 32-bit bytes
  /// - [hl] is the second most-significant 32-bit bytes
  /// - [hh] is the most-significant 32-bit bytes
  ///
  /// Example:
  /// ```
  /// 128-bit number: 0x0102030405060708090A0B0C0D0E0F10
  ///    64-bit high: 0x0102030405060708
  ///      32-bit hh: 0x01020304
  ///      32-bit hl: 0x05060708
  ///    64-bit  low: 0x090A0B0C0D0E0F10
  ///      32-bit lh: 0x090A0B0C
  ///      32-bit ll: 0x0D0E0F10
  /// ```
  ///
  /// To get it in big-endian order use the [reverse] method.
  factory Nonce128.int32(
    int ll, [
    int lh = 0,
    int hl = 0,
    int hh = 0,
  ]) =>
      Nonce128._(
        Uint8List.fromList([
          ll,
          ll >>> 8,
          ll >>> 16,
          ll >>> 24,
          lh,
          lh >>> 8,
          lh >>> 16,
          lh >>> 24,
          hl,
          hl >>> 8,
          hl >>> 16,
          hl >>> 24,
          hh,
          hh >>> 8,
          hh >>> 16,
          hh >>> 24,
        ]),
      );

  @override
  Nonce128 reverse() => Nonce128._(_reverseBytes(bytes));
}
