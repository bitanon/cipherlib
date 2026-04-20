// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

@pragma('vm:prefer-inline')
int _validateSize(Uint8List block, int? size) {
  if (size == null) {
    return block.length;
  } else if (size < 0 || size > block.length) {
    throw StateError('Invalid block size');
  }
  return size;
}

/// Padding is a process to extend the input message to match a specific
/// block size to be used in the cryptographic algorithms.
///
/// Reference: https://en.wikipedia.org/wiki/Padding_(cryptography)
abstract class Padding {
  const Padding();

  /// The name of the algorithm
  String get name;

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
  static const ansi = _ANSIPadding();

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
  bool pad(Uint8List block, int pos, [int? size]);

  /// Returns the padding length from the [block] according to the scheme.
  ///
  /// Throws [StateError] on malformatted block.
  int getPadLength(Uint8List block, [int? size]);

  /// Returns the original message after removing padding from the [block]
  /// using the scheme.
  @pragma('vm:prefer-inline')
  Uint8List unpad(Uint8List block, [int? size]) {
    size ??= block.length;
    int p = getPadLength(block, size);
    return block.sublist(0, size - p);
  }
}

class _NonePadding implements Padding {
  @override
  final String name = "NoPadding";

  const _NonePadding();

  @override
  @pragma('vm:prefer-inline')
  bool pad(Uint8List block, int pos, [int? size]) => false;

  @override
  @pragma('vm:prefer-inline')
  int getPadLength(Uint8List block, [int? size]) => 0;

  @override
  @pragma('vm:prefer-inline')
  Uint8List unpad(Uint8List block, [int? size]) {
    if (size == null || size == block.length) {
      return block;
    }
    if (size < 0 || size > block.length) {
      throw StateError('Invalid block size');
    }
    return block.sublist(0, size);
  }
}

class _ZeroPadding extends Padding {
  @override
  final String name = "Zero";

  const _ZeroPadding();

  @override
  @pragma('vm:prefer-inline')
  bool pad(Uint8List block, int pos, [int? size]) {
    size = _validateSize(block, size);
    if (pos < 0 || pos >= size) {
      throw StateError('No space for padding');
    }
    block.fillRange(pos, size, 0);
    return true;
  }

  @override
  @pragma('vm:prefer-inline')
  int getPadLength(Uint8List block, [int? size]) {
    size = _validateSize(block, size);
    int p = size - 1;
    while (p >= 0 && block[p] == 0) {
      p--;
    }
    return size - 1 - p;
  }
}

class _BytePadding extends Padding {
  @override
  final String name = "Byte";

  const _BytePadding();

  @override
  @pragma('vm:prefer-inline')
  bool pad(Uint8List block, int pos, [int? size]) {
    size = _validateSize(block, size);
    if (pos < 0 || pos >= size) {
      throw StateError('No space for padding');
    }
    block[pos] = 0x80;
    if (pos + 1 < size) {
      block.fillRange(pos + 1, size, 0);
    }
    return true;
  }

  @override
  @pragma('vm:prefer-inline')
  int getPadLength(Uint8List block, [int? size]) {
    size = _validateSize(block, size);
    for (int p = size - 1; p >= 0; p--) {
      int b = block[p];
      if (b == 0x80) {
        return size - p;
      }
      if (b != 0) {
        throw StateError('Invalid padding');
      }
    }
    throw StateError('Invalid padding');
  }
}

class _ANSIPadding extends Padding {
  @override
  final String name = "ANSI";

  const _ANSIPadding();

  @override
  @pragma('vm:prefer-inline')
  bool pad(Uint8List block, int pos, [int? size]) {
    size = _validateSize(block, size);
    if (pos < 0 || pos >= size) {
      throw StateError('No space for padding');
    }
    int n = size - pos;
    if (n > 255) {
      throw StateError('Padding size must not exceed 255 bytes');
    }
    if (pos < size - 1) {
      block.fillRange(pos, size - 1, 0);
    }
    block[size - 1] = n;
    return true;
  }

  @override
  @pragma('vm:prefer-inline')
  int getPadLength(Uint8List block, [int? size]) {
    size = _validateSize(block, size);
    if (size == 0) {
      throw StateError('Invalid padding');
    }
    int n = block[size - 1];
    if (n == 0 || size < n) {
      throw StateError('Invalid padding');
    }
    int end = size - 1;
    for (int p = size - n; p < end; p++) {
      if (block[p] != 0) {
        throw StateError('Invalid padding');
      }
    }
    return n;
  }
}

class _PKCS7Padding extends Padding {
  @override
  String get name => "PKCS7";

  const _PKCS7Padding();

  @override
  @pragma('vm:prefer-inline')
  bool pad(Uint8List block, int pos, [int? size]) {
    size = _validateSize(block, size);
    if (pos < 0 || pos >= size) {
      throw StateError('No space for padding');
    }
    int n = size - pos;
    if (n > 255) {
      throw StateError('Padding size must not exceed 255 bytes');
    }
    block.fillRange(pos, size, n);
    return true;
  }

  @override
  @pragma('vm:prefer-inline')
  int getPadLength(Uint8List block, [int? size]) {
    size = _validateSize(block, size);
    if (size == 0) {
      throw StateError('Invalid padding');
    }
    int n = block[size - 1];
    if (n == 0 || size < n) {
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
  @override
  final String name = "PKCS5";

  const _PKCS5Padding();

  @override
  @pragma('vm:prefer-inline')
  bool pad(Uint8List block, int pos, [int? size]) {
    size = _validateSize(block, size);
    if (pos < 0 || pos >= size) {
      throw StateError('No space for padding');
    }
    if (size != 8) {
      throw StateError('Block must be exactly 64-bit');
    }
    block.fillRange(pos, size, size - pos);
    return true;
  }
}
