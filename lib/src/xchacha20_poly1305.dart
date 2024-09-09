// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/src/algorithms/aead_cipher.dart';
import 'package:cipherlib/src/algorithms/chacha20.dart';
import 'package:cipherlib/src/utils/nonce.dart';
import 'package:hashlib/hashlib.dart' show Poly1305;

/// XChaCha20-Poly1305 is a cryptographic algorithm combining [XChaCha20]
/// stream cipher for encryption and [Poly1305] for generating message
/// authentication code.
///
/// This implementation is based on the [RFC-8439][rfc]
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc8439.html
class XChaCha20Poly1305 extends AEADCipher<XChaCha20, Poly1305> {
  const XChaCha20Poly1305._(
    XChaCha20 cipher,
    Poly1305 mac,
    List<int>? aad,
  ) : super(cipher, mac, aad);

  /// Creates a new instance of the [XChaCha20Poly1305] cipher.
  ///
  /// Parameters:
  /// - [key] : Either 16 or 32 bytes key.
  /// - [nonce] : Either 8 or 12 bytes nonce.
  /// - [aad] : Additional authenticated data.
  /// - [counter] : Initial block number.
  factory XChaCha20Poly1305({
    required List<int> key,
    List<int>? nonce,
    Nonce64? counter,
    List<int>? aad,
  }) =>
      XChaCha20(key, nonce, counter).poly1305(aad);

  @override
  @pragma('vm:prefer-inline')
  AEADResultWithIV convert(List<int> message) => sign(message);

  @override
  @pragma('vm:prefer-inline')
  AEADResultWithIV sign(List<int> message) =>
      super.sign(message).withIV(cipher.iv);
}

/// Adds [poly1305] to [XChaCha20] to create an instance of [XChaCha20Poly1305]
extension XChaCha20ExtentionForPoly1305 on XChaCha20 {
  /// Creates an instance of [XChaCha20Poly1305] that uses [XChaCha20] for
  /// message encryption and [Poly1305] for MAC (Message Authentication Code)
  /// generation to ensure data integrity.
  ///
  /// The [Poly1305] hash instance is initialized by a 32-byte long OTK.
  @pragma('vm:prefer-inline')
  XChaCha20Poly1305 poly1305([List<int>? aad]) =>
      XChaCha20Poly1305._(this, Poly1305($otk()), aad);
}

/// Transforms [message] with XChaCha20 algorithm and generates the message
/// digest with Poly1305 authentication code generator.
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : Either 16 or 32 bytes key.
/// - [nonce] : Either 8 or 12 bytes nonce.
/// - [aad] : Additional authenticated data.
/// - [counter] : Initial block number.
/// - [mac] : A 128-bit or 16-bytes long authentication tag for verification.
///
/// Throws: [AssertionError] on [mac] verification failure.
///
/// Both the encryption and decryption can be done using this same method.
AEADResultWithIV xchacha20poly1305(
  List<int> message,
  List<int> key, {
  List<int>? mac,
  List<int>? nonce,
  List<int>? aad,
  Nonce64? counter,
}) {
  var algo = XChaCha20Poly1305(
    key: key,
    nonce: nonce,
    counter: counter,
    aad: aad,
  );
  if (mac != null && !algo.verify(message, mac)) {
    throw AssertionError('Message authenticity check failed');
  }
  return algo.convert(message);
}
