// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show Poly1305;

import 'algorithms/aead_cipher.dart';
import 'algorithms/salsa20.dart';
import 'core/cipher.dart';
import 'utils/nonce.dart';

/// Salsa20-Poly1305 is a cryptographic algorithm combining the [Salsa20]
/// stream cipher for encryption and the [Poly1305] for generating message
/// authentication code.
///
/// This class can not be instantiated directly, instead use this method:
/// ```dart
/// final algo = Salsa20(key, nonce, counter).poly1305(aad);
/// ```
class Salsa20Poly1305 extends AEADCipher<Salsa20, Poly1305> with SaltedCipher {
  const Salsa20Poly1305._(super.cipher, super.algo);

  @override
  Uint8List get iv => cipher.iv;

  @override
  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  void resetIV() {
    cipher.resetIV();
    algo.keypair.setAll(0, cipher.$otk());
  }

  @override
  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  AEADResultWithIV sign(List<int> message, [List<int>? aad]) =>
      super.sign(message, aad).withIV(cipher.iv);
}

/// Adds [poly1305] to [Salsa20] to create an instance of [Salsa20Poly1305]
extension Salsa20ExtentionForPoly1305 on Salsa20 {
  /// Create an instance of [Salsa20Poly1305] that uses [Salsa20] for message
  /// encryption and [Poly1305] for MAC (Message Authentication Code) generation
  /// to ensure data integrity.
  ///
  /// The [Poly1305] hash instance is initialized by a 32-byte long OTK.
  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  Salsa20Poly1305 poly1305() => Salsa20Poly1305._(this, Poly1305($otk()));
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
/// Throws: [StateError] on [mac] verification failure.
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
  final algo = Salsa20(key, nonce, counter).poly1305();
  if (mac != null && !algo.verify(message, mac, aad)) {
    throw StateError('Message authenticity check failed');
  }
  return algo.sign(message, aad);
}
