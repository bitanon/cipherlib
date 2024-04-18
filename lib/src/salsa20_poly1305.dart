// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/src/algorithms/salsa20_poly1305.dart';
import 'package:cipherlib/src/core/authenticator.dart';
import 'package:hashlib/hashlib.dart' show HashDigest;

export 'algorithms/salsa20_poly1305.dart' show Salsa20Poly1305;

/// Generate only the [message] digest using [Salsa20Poly1305].
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : A 16 or 32-bytes long key.
/// - [nonce] : A 16-bytes long nonce. Deafult: 0
/// - [aad] : Additional authenticated data.
HashDigest salsa20poly1305Digest(
  List<int> message,
  List<int> key, {
  List<int>? nonce,
  List<int>? aad,
}) =>
    Salsa20Poly1305(key).digest(
      message,
      nonce: nonce,
      aad: aad,
    );

/// Verify the [message] digest using [Salsa20Poly1305].
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : A 16 or 32-bytes long key.
/// - [nonce] : A 16-bytes long nonce. Deafult: 0
/// - [aad] : Additional authenticated data.
bool salsa20poly1305Verify(
  List<int> message,
  List<int> key,
  List<int> mac, {
  List<int>? nonce,
  List<int>? aad,
}) =>
    Salsa20Poly1305(key).verify(
      message,
      mac,
      nonce: nonce,
      aad: aad,
    );

/// Transforms [message] with Salsa20 algorithm and generates the message
/// digest with Poly1305 authentication code generator.
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : A 16 or 32-bytes long key.
/// - [nonce] : A 16-bytes long nonce. Deafult: 0
/// - [aad] : Additional authenticated data.
/// - [mac] : A 128-bit or 16-bytes long authentication tag for verification.
///
/// Both the encryption and decryption can be done using this same method.
CipherMAC salsa20poly1305(
  List<int> message,
  List<int> key, {
  List<int>? mac,
  List<int>? nonce,
  List<int>? aad,
}) =>
    Salsa20Poly1305(key).convertWithDigest(
      message,
      mac: mac,
      nonce: nonce,
      aad: aad,
    );

/// Transforms [stream] with Salsa20 algorithm and generates the message
/// digest with Poly1305 authentication code generator.
///
/// Parameters:
/// - [stream] : arbitrary length plain-text.
/// - [key] : A 16 or 32-bytes long key.
/// - [nonce] : A 16-bytes long nonce. Deafult: 0
/// - [aad] : Additional authenticated data.
/// - [mac] : A 128-bit or 16-bytes long authentication tag for verification.
///
/// Both the encryption and decryption can be done using this same method.
AsyncCipherMAC salsa20poly1305Stream(
  Stream<int> stream,
  List<int> key, {
  Future<HashDigest>? mac,
  List<int>? nonce,
  List<int>? aad,
}) =>
    Salsa20Poly1305(key).streamWithDigest(
      stream,
      mac: mac,
      nonce: nonce,
      aad: aad,
    );
