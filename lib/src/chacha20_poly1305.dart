// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show Poly1305;

import 'algorithms/aead_cipher.dart';
import 'algorithms/chacha20.dart';
import 'core/cipher.dart';
import 'utils/nonce.dart';

/// ChaCha20-Poly1305 is a cryptographic algorithm combining [ChaCha20]
/// stream cipher for encryption and [Poly1305] for generating message
/// authentication code.
/// It provides both confidentiality and integrity protection, making it a
/// popular choice for secure communication protocols like TLS.
///
///
/// This class can not be instantiated directly, instead use this method:
/// ```dart
/// final algo = ChaCha20(key, nonce, counter).poly1305(aad);
/// ```
///
/// This implementation is based on the [RFC-8439][rfc]
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc8439.html
class ChaCha20Poly1305 extends AEADCipher<ChaCha20, Poly1305>
    with SaltedCipher {
  const ChaCha20Poly1305._(super.cipher, super.algo);

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

/// Adds [poly1305] to [ChaCha20] to create an instance of [ChaCha20Poly1305]
extension ChaCha20ExtentionForPoly1305 on ChaCha20 {
  /// Create an instance of [ChaCha20Poly1305] that uses [ChaCha20] for message
  /// encryption and [Poly1305] for MAC (Message Authentication Code) generation
  /// to ensure data integrity.
  ///
  /// The [Poly1305] hash instance is initialized by a 32-byte long OTK.
  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  ChaCha20Poly1305 poly1305() => ChaCha20Poly1305._(this, Poly1305($otk()));
}

/// Encrypts or Decrypts the [message] using ChaCha20 cipher and generates an
/// authentication tag with Poly1305.
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : Either 16 or 32 bytes key.
/// - [nonce] : Either 8 or 12 bytes nonce.
/// - [aad] : Additional authenticated data.
/// - [counter] : Initial block number.
/// - [mac] : A 128-bit or 16-bytes long authentication tag for verification.
///
/// Throws: [StateError] on [mac] verification failure.
///
/// Both the encryption and decryption can be done using this same method.
AEADResultWithIV chacha20poly1305(
  List<int> message,
  List<int> key, {
  List<int>? mac,
  List<int>? nonce,
  List<int>? aad,
  Nonce64? counter,
}) {
  final algo = ChaCha20(key, nonce, counter).poly1305();
  if (mac != null && !algo.verify(message, mac, aad)) {
    throw StateError('Message authenticity check failed');
  }
  return algo.sign(message, aad);
}
