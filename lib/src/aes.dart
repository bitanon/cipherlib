// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aes/aes_ecb.dart';
import 'package:cipherlib/src/core/cipher.dart';

/// AES (Advanced Encryption Standard) is a symmetric encryption algorithm used
/// for securing data. It operates on fixed-size blocks of data (128 bits) using
/// keys of 128, 192, or 256 bits.
///
/// The process involves multiple rounds of substitution, permutation, mixing,
/// and key addition to transform plaintext into ciphertext. Decryption reverses
/// this process, using the same key to recover the original plaintext.
///
/// AES is known for its high speed and strong security, making it suitable for
/// various applications,including data protection in software and hardware.
class AES {
  final List<int> key;

  /// Initialize the instance with a [key] for encryption and decryption
  const AES(this.key);

  /// ECB (Electronic Codebook) mode for AES works by dividing the plaintext
  /// into fixed-size blocks (128 bits) and processing each block independently
  /// using the same key.
  ///
  /// > Note that, the input message size must be a multiple of 16 for ECB mode.
  ///
  /// **Not Recommended: It is vulnerable to pattern analysis.**
  AESInECBMode ecb() => AESInECBMode(key);
}

/// Operational modes for [AES] ciphers
enum AESMode {
  ecb,
}

extension on AES {
  CollateCipher fromMode(AESMode mode) {
    switch (mode) {
      case AESMode.ecb:
        return ecb();
      default:
        throw ArgumentError('Unknown mode');
    }
  }
}

/// Encrypts a message with [AES] cipher.
Uint8List aesEncrypt(
  List<int> message,
  List<int> key, {
  AESMode mode = AESMode.ecb,
}) =>
    AES(key).fromMode(mode).encrypt(message);

/// Decrypts a message with [AES] cipher.
Uint8List aesDecrypt(
  List<int> message,
  List<int> key, {
  AESMode mode = AESMode.ecb,
}) =>
    AES(key).fromMode(mode).decrypt(message);
