// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/src/algorithms/chacha20_poly1305.dart';
import 'package:hashlib/hashlib.dart' show HashDigest;

export 'algorithms/chacha20_poly1305.dart';

/// Transforms [message] with ChaCha20 algorithm and generates the message
/// digest with Poly1305 authentication code generator.
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : Either 16 or 32 bytes key.
/// - [nonce] : Either 8 or 12 bytes nonce.
/// - [aad] : Additional authenticated data.
/// - [mac] : A 128-bit or 16-bytes long authentication tag for verification.
///
/// Throws: [AssertionError] on [mac] verification failure.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
HashDigest chacha20poly1305(
  List<int> message,
  List<int> key, {
  List<int>? mac,
  List<int>? nonce,
  List<int>? aad,
}) =>
    ChaCha20Poly1305(
      key: key,
      iv: nonce ?? Uint32List(12),
      aad: aad,
    ).verify(message, mac);

/// Transforms [stream] with ChaCha20 algorithm and generates the message
/// digest with Poly1305 authentication code generator.
///
/// Parameters:
/// - [stream] : arbitrary length plain-text.
/// - [key] : Either 16 or 32 bytes key.
/// - [nonce] : Either 8 or 12 bytes nonce.
/// - [aad] : Additional authenticated data.
/// - [mac] : A 128-bit or 16-bytes long authentication tag for verification.
///
/// Throws: [AssertionError] on [mac] verification failure.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Future<HashDigest> chacha20poly1305Stream(
  Stream<int> stream,
  List<int> key, {
  Future<List<int>>? mac,
  List<int>? nonce,
  List<int>? aad,
}) =>
    ChaCha20Poly1305(
      key: key,
      iv: nonce ?? Uint32List(12),
      aad: aad,
    ).verifyStream(stream, mac);
