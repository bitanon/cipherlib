// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/src/algorithms/chacha20_poly1305.dart';
import 'package:cipherlib/src/core/auth_cipher.dart';
import 'package:hashlib/hashlib.dart';

export 'algorithms/chacha20_poly1305.dart' show ChaCha20Poly1305;

/// Encrypts [message] with ChaCha20 algorithm and generates the message digest
/// by Poly1305 for authentication.
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : A 256-bit or 32-bytes long key.
/// - [nonce] : A 96-bit or 12-bytes long nonce.
/// - [aad] : Additional authenticated data.
/// - [tag] : A 128-bit or 16-bytes long authentication tag for verification.
///
/// Both the encryption and decryption can be done using this same method.
AuthCipherResult chacha20poly1305(
  List<int> message,
  List<int> key, {
  List<int>? tag,
  List<int>? nonce,
  List<int>? aad,
}) {
  var instance = ChaCha20Poly1305(key);
  if (tag != null) {
    if (!instance.verify(message, tag, nonce: nonce, aad: aad)) {
      throw StateError('Invalid tag');
    }
  }
  var cipher = instance.convert(message, nonce: nonce);
  var cipherTag = instance.digest(cipher, nonce: nonce, aad: aad);
  return AuthCipherResult(cipher, cipherTag);
}

/// Generate only the [message] digest using [ChaCha20Poly1305].
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : A 256-bit or 32-bytes long key.
/// - [nonce] : A 96-bit or 12-bytes long nonce.
/// - [aad] : Additional authenticated data.
///
/// Both the encryption and decryption can be done using this same method.
HashDigest chacha20poly1095digest(
  List<int> message,
  List<int> key, {
  List<int>? nonce,
  List<int>? aad,
}) {
  return ChaCha20Poly1305(key).digest(message, nonce: nonce, aad: aad);
}
