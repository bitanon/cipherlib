// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show HashDigest;

/// Mixin for ciphers relying on authentication tag.
mixin Authenticator {
  /// Generates the authentication tag for the [message].
  HashDigest digest(List<int> message);

  /// Verify the [message] against the authentication [tag].
  bool verify(List<int> message, List<int> tag) {
    var current = digest(message);
    return current.isEqual(tag);
  }
}

/// Combined result of encrypted [cipher] text with the authentication [tag].
class AuthCipherResult {
  /// The authentication tag.
  final HashDigest tag;

  /// The cipher text.
  final Uint8List cipher;

  /// Creates a new instance of [AuthCipherResult]
  const AuthCipherResult(this.cipher, this.tag);
}
