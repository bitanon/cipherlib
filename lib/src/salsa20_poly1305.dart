// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/src/algorithms/salsa20_poly1305.dart';
import 'package:cipherlib/src/core/aead_cipher.dart';
import 'package:hashlib/hashlib.dart' show randomBytes;

export 'algorithms/salsa20_poly1305.dart';

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
}) =>
    Salsa20Poly1305(
      key: key,
      iv: nonce ?? randomBytes(16),
      aad: aad,
    ).verify(message, mac);
