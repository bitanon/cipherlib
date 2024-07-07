// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aead_cipher.dart';
import 'package:cipherlib/src/algorithms/salsa20.dart';
import 'package:hashlib/hashlib.dart' show Poly1305, randomBytes;

/// Salsa20-Poly1305 is a cryptographic algorithm combining the [Salsa20]
/// stream cipher for encryption and the [Poly1305] for generating message
/// authentication code.
class Salsa20Poly1305 extends AEADCipher<Salsa20, Poly1305> {
  const Salsa20Poly1305._(
    Salsa20 cipher,
    Poly1305 mac,
    List<int>? aad,
  ) : super(cipher, mac, aad);

  factory Salsa20Poly1305({
    required List<int> key,
    required List<int> iv,
    List<int>? aad,
  }) =>
      Salsa20.fromList(key, iv).poly1305(aad);

  @override
  @pragma('vm:prefer-inline')
  AEADResult convert(List<int> message) {
    return super.convert(message).withIV(cipher.iv);
  }
}

/// Adds [poly1305] to [Salsa20] to create an instance of [Salsa20Poly1305]
extension Salsa20ExtentionForPoly1305 on Salsa20 {
  @pragma('vm:prefer-inline')
  Salsa20Poly1305 poly1305([List<int>? aad]) {
    var otk = Salsa20Sink(key, iv, 0).add(Uint8List(32));
    return Salsa20Poly1305._(this, Poly1305(otk), aad);
  }
}

/// Transforms [message] with Salsa20 algorithm and generates the message
/// digest with Poly1305 authentication code generator.
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : Either 16 or 32 bytes key.
/// - [nonce] : Either 8 or 16 bytes nonce.
/// - [aad] : Additional authenticated data.
/// - [mac] : A 128-bit or 16-bytes long authentication tag for verification.
///
/// Throws: [AssertionError] on [mac] verification failure.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
AEADResult salsa20poly1305(
  List<int> message,
  List<int> key, {
  List<int>? mac,
  List<int>? nonce,
  List<int>? aad,
}) {
  var algo = Salsa20Poly1305(
    key: key,
    iv: nonce ?? randomBytes(12),
    aad: aad,
  );
  if (mac != null && !algo.verify(message, mac)) {
    throw AssertionError('Message authenticity check failed');
  }
  return algo.convert(message);
}
