// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/src/algorithms/aead_cipher.dart';
import 'package:cipherlib/src/algorithms/salsa20.dart';
import 'package:cipherlib/src/utils/nonce.dart';
import 'package:hashlib/hashlib.dart' show Poly1305;

/// XSalsa20-Poly1305 is a cryptographic algorithm combining the [XSalsa20]
/// stream cipher for encryption and the [Poly1305] for generating message
/// authentication code.
class XSalsa20Poly1305 extends AEADCipher<XSalsa20, Poly1305> {
  const XSalsa20Poly1305._(
    XSalsa20 cipher,
    Poly1305 mac,
    List<int>? aad,
  ) : super(cipher, mac, aad);

  /// Creates a new instance of the [XSalsa20Poly1305] cipher.
  ///
  /// Parameters:
  /// - [key] : Either 16 or 32 bytes key.
  /// - [nonce] : Either 8 or 16 bytes nonce.
  /// - [aad] : Additional authenticated data.
  /// - [counter] : Initial block number.
  factory XSalsa20Poly1305({
    required List<int> key,
    List<int>? nonce,
    Nonce64? counter,
    List<int>? aad,
  }) =>
      XSalsa20(key, nonce, counter).poly1305(aad);

  @override
  @pragma('vm:prefer-inline')
  AEADResultWithIV convert(List<int> message) => sign(message);

  @override
  @pragma('vm:prefer-inline')
  AEADResultWithIV sign(List<int> message) =>
      super.sign(message).withIV(cipher.iv);
}

/// Adds [poly1305] to [XSalsa20] to create an instance of [XSalsa20Poly1305]
extension XSalsa20ExtentionForPoly1305 on XSalsa20 {
  /// Creates an instance of [XSalsa20Poly1305] that uses [XSalsa20] for message
  /// encryption and [Poly1305] for MAC (Message Authentication Code) generation
  /// to ensure data integrity.
  ///
  /// The [Poly1305] hash instance is initialized by a 32-byte long OTK.
  @pragma('vm:prefer-inline')
  XSalsa20Poly1305 poly1305([List<int>? aad]) {
    return XSalsa20Poly1305._(this, Poly1305($otk()), aad);
  }
}

/// Transforms [message] with XSalsa20 algorithm and generates the message
/// digest with Poly1305 authentication code generator.
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : Either 16 or 32 bytes key.
/// - [nonce] : Either 8 or 16 bytes nonce.
/// - [aad] : Additional authenticated data.
/// - [counter] : Initial block number.
/// - [mac] : A 128-bit or 16-bytes long authentication tag for verification.
///
/// Throws: [AssertionError] on [mac] verification failure.
///
/// Both the encryption and decryption can be done using this same method.
AEADResultWithIV xsalsa20poly1305(
  List<int> message,
  List<int> key, {
  List<int>? mac,
  List<int>? nonce,
  List<int>? aad,
  Nonce64? counter,
}) {
  var algo = XSalsa20Poly1305(
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
