// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show fillNumbers;

/// Padding is a process to extend the input message to match a specific
/// block size to be used in the cryptographic algorithms.
///
/// Reference: https://en.wikipedia.org/wiki/Padding_(cryptography)
abstract class Padding {
  const Padding();

  /// Does not apply any padding. The message size is always expected to be
  /// equal to the block size.
  static const none = _NonePadding();

  /// Padding with zeros to match the block size.
  ///
  /// ### Example: ###
  /// 5-bytes message to 8-bytes block:
  /// ```
  /// ... | FA 3D E6 61 1C |
  /// ... | FA 3D E6 61 1C 00 00 00 |
  ///                      ** -- -- |
  /// ```
  static const zero = _ZeroPadding();

  /// This padding has `0x80` as the first byte followed by a sequence of zeros.
  /// It was originally defined as a communication standard for smart cards
  /// containing a file system in [ISO/IEC 7816-4:2005][iso].
  ///
  /// ### Example: ###
  /// 5-bytes message to 8-bytes block:
  /// ```
  /// ... | FA 3D E6 61 1C |
  /// ... | FA 3D E6 61 1C 80 00 00 |
  ///                      ** -- -- |
  /// ```
  ///
  /// [iso]: https://www.iso.org/standard/36134.html
  static const byte = _BytePadding();

  /// This ANSI X9.23 standard padding consists of a sequence of zeros with the
  /// last byte set to the number of padding bytes added, including itself. If
  /// the input size is already a multiple of the block size, an extra block of
  /// padding is added.
  ///
  /// _Limitation: Maximum block size must be less than 256 bytes_
  ///
  /// ### Example: ###
  /// 4-bytes message to 8-bytes block:
  /// ```
  /// ... | FA 3D E6 61 |
  /// ... | FA 3D E6 61 00 00 00 04 |
  ///                   -- -- -- ** |
  /// ```
  static const ansiX923 = _ANSIx923Padding();

  /// This is similar to [ansiX923] scheme, except instead of filling with a
  /// sequence of zeros, random bytes are inserted as padding.
  ///
  /// Defined in [ISO 10126-1:1991][iso] a.k.a. "Banking — Procedures for message
  /// encipherment (wholesale)"
  ///
  /// https://www.iso.org/standard/18113.html
  ///
  /// _Limitation: Maximum block size must be less than 256 bytes_
  ///
  /// ### Example: ###
  /// 4-bytes message to 8-bytes block:
  /// ```
  /// ... | FA 3D E6 61 |
  /// ... | FA 3D E6 61 81 A6 23 04 |
  ///                   -- -- -- ** |
  /// ```
  ///
  /// [iso]: https://www.iso.org/standard/18113.html
  static const iso10126 = _ISO10126Padding();

  /// Padding is in whole bytes. The value of each added byte is the number of
  /// bytes that are added. If the input size is already a multiple of the block
  /// size, an extra block of padding is added.
  ///
  /// It is described in [RFC-5652][rfc] a.k.a. Cryptographic Message Syntax (CMS)
  ///
  /// _Limitation: Maximum block size must be less than 256 bytes_
  ///
  /// ### Example: ###
  /// 4-bytes message to 8-bytes block:
  /// ```
  /// ... | FA 3D E6 61 |
  /// ... | FA 3D E6 61 04 04 04 04 |
  ///                   ** -- -- -- |
  /// ```
  ///
  /// [rfc]: https://datatracker.ietf.org/doc/html/rfc5652#section-6.3
  static const pkcs7 = _PKCS7Padding();

  /// Same as [pkcs7] padding scheme, except it is only defined for exactly
  /// 64-bit block. Primarily used with DES and other algorithms with an
  /// 8-byte block size.
  ///
  /// _Limitation: Maximum block size must be exactly 8 bytes_
  ///
  /// ### Example: ###
  /// 4-bytes message to 8-bytes block:
  /// ```
  /// ... | FA 3D E6 61 |
  /// ... | FA 3D E6 61 04 04 04 04 |
  ///                   ** -- -- -- |
  /// ```
  static const pkcs5 = _PKCS5Padding();

  /// Apply the scheme to the input [block]. The padding is applied starting
  /// from the [pos] to the end of the [block].
  ///
  /// Throws [StateError] if block has no space left for padding, or fails
  /// matching some constraints of specific schemes.
  ///
  /// Returns true if the padding was applied, false otherwise.
  bool pad(List<int> block, int pos, [int? size]);

  /// Returns the padding length from the [block] according to the scheme.
  ///
  /// Throws [StateError] on malformatted block.
  int getPadLength(List<int> block, [int? size]);

  /// Returns the original message after removing padding from the [block]
  /// using the scheme.
  List<int> unpad(List<int> block, [int? size]) {
    size ??= block.length;
    int p = getPadLength(block, size);
    if (p == size) {
      return Uint8List(0);
    }
    return block.sublist(0, size - p);
  }
}

class _NonePadding extends Padding {
  const _NonePadding();

  @override
  bool pad(List<int> block, int pos, [int? size]) {
    return false;
  }

  @override
  int getPadLength(List<int> block, [int? size]) {
    return 0;
  }
}

class _ZeroPadding extends Padding {
  const _ZeroPadding();

  @override
  bool pad(List<int> block, int pos, [int? size]) {
    size ??= block.length;
    for (; pos < size; pos++) {
      block[pos] = 0;
    }
    return true;
  }

  @override
  int getPadLength(List<int> block, [int? size]) {
    size ??= block.length;
    int p;
    for (p = size; p > 0; p--) {
      if (block[p - 1] != 0) {
        break;
      }
    }
    return size - p;
  }
}

class _BytePadding extends Padding {
  const _BytePadding();

  @override
  bool pad(List<int> block, int pos, [int? size]) {
    size ??= block.length;
    if (pos >= size) {
      throw StateError('No space for padding');
    }
    block[pos++] = 0x80;
    for (; pos < size; pos++) {
      block[pos] = 0;
    }
    return true;
  }

  @override
  int getPadLength(List<int> block, [int? size]) {
    size ??= block.length;
    int p;
    for (p = size - 1; p >= 0; p--) {
      if (block[p] == 0x80) {
        break;
      } else if (block[p] != 0) {
        throw StateError('Invalid padding');
      }
    }
    if (p < 0) {
      throw StateError('Invalid padding');
    }
    return size - p;
  }
}

class _ANSIx923Padding extends Padding {
  const _ANSIx923Padding();

  @override
  bool pad(List<int> block, int pos, [int? size]) {
    size ??= block.length;
    if (pos >= size) {
      throw StateError('No space for padding');
    }
    int n = size - pos;
    if (n > 255) {
      throw StateError('Padding size must not exceed 255 bytes');
    }
    for (; pos < size; pos++) {
      block[pos] = 0;
    }
    block[pos - 1] = n;
    return true;
  }

  @override
  int getPadLength(List<int> block, [int? size]) {
    size ??= block.length;
    int n = block[size - 1];
    if (size < n) {
      throw StateError('Invalid padding');
    }
    for (int p = size - n; p < size - 1; p++) {
      if (block[p] != 0) {
        throw StateError('Invalid padding');
      }
    }
    return n;
  }
}

class _ISO10126Padding extends Padding {
  const _ISO10126Padding();

  @override
  bool pad(List<int> block, int pos, [int? size]) {
    size ??= block.length;
    if (pos >= size) {
      throw StateError('No space for padding');
    }
    int n = size - pos;
    if (n > 255) {
      throw StateError('Padding size must not exceed 255 bytes');
    }
    fillNumbers(block, start: pos);
    block[pos - 1] = n;
    return true;
  }

  @override
  int getPadLength(List<int> block, [int? size]) {
    size ??= block.length;
    int n = block[size - 1];
    if (size < n) {
      throw StateError('Invalid padding');
    }
    return n;
  }
}

class _PKCS7Padding extends Padding {
  const _PKCS7Padding();

  @override
  bool pad(List<int> block, int pos, [int? size]) {
    size ??= block.length;
    if (pos >= size) {
      throw StateError('No space for padding');
    }
    int n = size - pos;
    if (n > 255) {
      throw StateError('Padding size must not exceed 255 bytes');
    }
    for (; pos < size; pos++) {
      block[pos] = n;
    }
    return true;
  }

  @override
  int getPadLength(List<int> block, [int? size]) {
    size ??= block.length;
    int n = block[size - 1];
    if (size < n) {
      throw StateError('Invalid padding');
    }
    for (int p = size - n; p < size; p++) {
      if (block[p] != n) {
        throw StateError('Invalid padding');
      }
    }
    return n;
  }
}

class _PKCS5Padding extends _PKCS7Padding {
  const _PKCS5Padding();

  @override
  bool pad(List<int> block, int pos, [int? size]) {
    size ??= block.length;
    if (pos >= size) {
      throw StateError('No space for padding');
    }
    if (size != 8) {
      throw StateError('Block must be exactly 64-bit');
    }
    int n = size - pos;
    for (; pos < size; pos++) {
      block[pos] = n;
    }
    return true;
  }
}
