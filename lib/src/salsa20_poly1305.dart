// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aead_cipher.dart';
import 'package:cipherlib/src/algorithms/salsa20.dart';
import 'package:cipherlib/src/core/cipher.dart';
import 'package:cipherlib/src/utils/nonce.dart';
import 'package:hashlib/hashlib.dart' show Poly1305;

/// Salsa20-Poly1305 is a cryptographic algorithm combining the [Salsa20]
/// stream cipher for encryption and the [Poly1305] for generating message
/// authentication code.
class Salsa20Poly1305 extends AEADCipher<Salsa20, Poly1305> with SaltedCipher {
  const Salsa20Poly1305._(
    Salsa20 cipher,
    Poly1305 mac,
    List<int>? aad,
  ) : super(cipher, mac, aad);

  /// Creates a new instance of the [Salsa20Poly1305] cipher.
  ///
  /// Parameters:
  /// - [key] : Either 16 or 32 bytes key.
  /// - [nonce] : Either 8 or 16 bytes nonce.
  /// - [aad] : Additional authenticated data.
  /// - [counter] : Initial block number.
  factory Salsa20Poly1305(
    List<int> key, {
    List<int>? nonce,
    Nonce64? counter,
    List<int>? aad,
  }) =>
      Salsa20(key, nonce, counter).poly1305(aad);

  @override
  @pragma('vm:prefer-inline')
  AEADResultWithIV sign(List<int> message) =>
      super.sign(message).withIV(cipher.iv);

  @override
  Uint8List get iv => cipher.iv;

  @override
  void resetIV() {
    cipher.resetIV();
    mac.keypair.setAll(0, cipher.$otk());
  }
}

/// Adds [poly1305] to [Salsa20] to create an instance of [Salsa20Poly1305]
extension Salsa20ExtentionForPoly1305 on Salsa20 {
  /// Create an instance of [Salsa20Poly1305] that uses [Salsa20] for message
  /// encryption and [Poly1305] for MAC (Message Authentication Code) generation
  /// to ensure data integrity.
  ///
  /// The [Poly1305] hash instance is initialized by a 32-byte long OTK.
  @pragma('vm:prefer-inline')
  Salsa20Poly1305 poly1305([List<int>? aad]) {
    return Salsa20Poly1305._(this, Poly1305($otk()), aad);
  }
}

/// Encrypts or Decrypts the [message] using Salsa20 cipher and generates an
/// authentication tag with Poly1305.
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
AEADResultWithIV salsa20poly1305(
  List<int> message,
  List<int> key, {
  List<int>? mac,
  List<int>? nonce,
  List<int>? aad,
  Nonce64? counter,
}) {
  var algo = Salsa20Poly1305(
    key,
    nonce: nonce,
    counter: counter,
    aad: aad,
  );
  if (mac != null && !algo.verify(message, mac)) {
    throw AssertionError('Message authenticity check failed');
  }
  return algo.sign(message);
}
