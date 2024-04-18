// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show HashDigest;

/// Mixin for ciphers relying on authentication tag.
abstract class Authenticator {
  /// Generates the authentication tag for the [message].
  HashDigest digest(List<int> message);

  /// Verify the [message] against the authentication [mac].
  bool verify(
    List<int> message,
    List<int> mac,
  ) {
    var current = digest(message);
    return current.isEqual(mac);
  }

  /// Transforms the [message] with an authentication tag.
  /// If [mac] is provided, it verifies the message integrity first.
  CipherMAC convertWithDigest(
    List<int> message, {
    List<int>? mac,
  });

  /// Transforms the [stream] with an autentication tag.
  /// If [mac] is provided, it verifies the message integrity first.
  AsyncCipherMAC streamWithDigest(
    Stream<int> stream, {
    Future<HashDigest>? mac,
  });
}

/// Combined result of encrypted [cipher] text with an authentication [mac].
class CipherMAC {
  /// The cipher text.
  final Uint8List cipher;

  /// The authentication tag.
  final HashDigest mac;

  const CipherMAC(this.cipher, this.mac);
}

/// Combined result of encrypted [cipher] text with an authentication [mac].
class AsyncCipherMAC {
  /// The cipher text.
  final Stream<int> cipher;

  /// The authentication tag.
  final Future<HashDigest> mac;

  const AsyncCipherMAC(this.cipher, this.mac);
}
