// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aead_cipher.dart';
import 'package:cipherlib/src/algorithms/chacha20.dart';
import 'package:cipherlib/src/utils/nonce.dart';
import 'package:hashlib/hashlib.dart' show Poly1305, randomBytes;

/// ChaCha20-Poly1305 is a cryptographic algorithm combining [ChaCha20]
/// stream cipher for encryption and [Poly1305] for generating message
/// authentication code.
/// It provides both confidentiality and integrity protection, making it a
/// popular choice for secure communication protocols like TLS.
///
/// This implementation is based on the [RFC-8439][rfc]
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc8439.html
class ChaCha20Poly1305 extends AEADCipher<ChaCha20, Poly1305> {
  const ChaCha20Poly1305._(
    ChaCha20 cipher,
    Poly1305 mac,
    List<int>? aad,
  ) : super(cipher, mac, aad);

  /// Creates a new instance of the [ChaCha20Poly1305] cipher.
  ///
  /// Parameters:
  /// - [key] : Either 16 or 32 bytes key.
  /// - [nonce] : Either 8 or 12 bytes nonce.
  /// - [aad] : Additional authenticated data.
  /// - [counter] : Initial block number.
  factory ChaCha20Poly1305({
    required List<int> key,
    required List<int> nonce,
    Nonce64? counter,
    List<int>? aad,
  }) =>
      ChaCha20.fromList(
        key,
        nonce: nonce,
        counter: counter,
      ).poly1305(aad);

  @override
  @pragma('vm:prefer-inline')
  AEADResultWithIV convert(List<int> message) {
    return super.convert(message).withIV(cipher.iv);
  }
}

/// Adds [poly1305] to [ChaCha20] to create an instance of [ChaCha20Poly1305]
extension ChaCha20ExtentionForPoly1305 on ChaCha20 {
  @pragma('vm:prefer-inline')
  ChaCha20Poly1305 poly1305([List<int>? aad]) {
    var otk = ChaCha20Sink(key, iv, Uint8List(8)).add(Uint8List(32));
    return ChaCha20Poly1305._(this, Poly1305(otk), aad);
  }
}

/// Transforms [message] with ChaCha20 algorithm and generates the message
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
@pragma('vm:prefer-inline')
AEADResultWithIV chacha20poly1305(
  List<int> message,
  List<int> key, {
  List<int>? mac,
  List<int>? nonce,
  List<int>? aad,
  Nonce64? counter,
}) {
  var algo = ChaCha20Poly1305(
    key: key,
    nonce: nonce ?? randomBytes(12),
    aad: aad,
  );
  if (mac != null && !algo.verify(message, mac)) {
    throw AssertionError('Message authenticity check failed');
  }
  return algo.convert(message);
}
