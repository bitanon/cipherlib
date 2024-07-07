// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show HashDigest;

import 'cipher.dart';

/// Mixin for ciphers with AEAD support
abstract class AEADCipher implements CipherBase {
  /// Generates the authentication tag for the [message].
  @pragma('vm:prefer-inline')
  AEADResult digest(List<int> message) => verify(message);

  /// Verify the [message] against the authentication code [mac],
  /// and throws an [AssertionError] on match failure.
  ///
  /// If [mac] is absent it returns the digest only without any verification.
  AEADResult verify(
    List<int> message, [
    List<int>? mac,
  ]);
}

/// The result fromo AEAD ciphers
class AEADResult {
  /// A random IV used for encryption. It can be null if and only if cipher does
  /// not support IV.
  final Uint8List? iv;

  /// The output message
  final Uint8List message;

  /// The message authentication code
  final HashDigest mac;

  const AEADResult({
    required this.message,
    required this.mac,
    this.iv,
  });
}
