// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/src/algorithms/chacha20_poly1305.dart';
import 'package:cipherlib/src/core/authenticator.dart';
import 'package:hashlib/hashlib.dart' show HashDigest;

export 'algorithms/chacha20_poly1305.dart' show ChaCha20Poly1305;

/// Generate only the [message] digest using [ChaCha20Poly1305].
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : A 32-bytes long key.
/// - [nonce] : A 12-bytes long nonce. Deafult: 0
/// - [aad] : Additional authenticated data.
HashDigest chacha20poly1305digest(
  List<int> message,
  List<int> key, {
  List<int>? nonce,
  List<int>? aad,
}) =>
    ChaCha20Poly1305(key).digest(
      message,
      nonce: nonce,
      aad: aad,
    );

/// Verify the [message] digest using [ChaCha20Poly1305].
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : A 32-bytes long key.
/// - [nonce] : A 12-bytes long nonce. Deafult: 0
/// - [aad] : Additional authenticated data.
bool chacha20poly1305verify(
  List<int> message,
  List<int> key,
  List<int> mac, {
  List<int>? nonce,
  List<int>? aad,
}) =>
    ChaCha20Poly1305(key).verify(
      message,
      mac,
      nonce: nonce,
      aad: aad,
    );

/// Transforms [message] with ChaCha20 algorithm and generates the message
/// digest with Poly1305 authentication code generator.
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : A 32-bytes long key.
/// - [nonce] : A 12-bytes long nonce. Deafult: 0
/// - [aad] : Additional authenticated data.
/// - [mac] : A 128-bit or 16-bytes long authentication tag for verification.
/// - [blockId] :  The initial block number. Default: 1.
///
/// Both the encryption and decryption can be done using this same method.
CipherMAC chacha20poly1305(
  List<int> message,
  List<int> key, {
  List<int>? mac,
  List<int>? nonce,
  List<int>? aad,
  int blockId = 1,
}) =>
    ChaCha20Poly1305(key).convertWithDigest(
      message,
      mac: mac,
      nonce: nonce,
      aad: aad,
      blockId: blockId,
    );

/// Transforms [stream] with ChaCha20 algorithm and generates the message
/// digest with Poly1305 authentication code generator.
///
/// Parameters:
/// - [stream] : arbitrary length plain-text.
/// - [key] : A 32-bytes long key.
/// - [nonce] : A 12-bytes long nonce. Deafult: 0
/// - [aad] : Additional authenticated data.
/// - [mac] : A 128-bit or 16-bytes long authentication tag for verification.
/// - [blockId] :  The initial block number. Default: 1.
///
/// Both the encryption and decryption can be done using this same method.
AsyncCipherMAC chacha20poly1305Stream(
  Stream<int> stream,
  List<int> key, {
  Future<HashDigest>? mac,
  List<int>? nonce,
  List<int>? aad,
  int blockId = 1,
}) =>
    ChaCha20Poly1305(key).streamWithDigest(
      stream,
      nonce: nonce,
      mac: mac,
      aad: aad,
      blockId: blockId,
    );
