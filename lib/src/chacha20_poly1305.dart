// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/src/algorithms/chacha20.dart';
import 'package:cipherlib/src/algorithms/chacha20_poly1305.dart';
import 'package:cipherlib/src/core/authenticator.dart';
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
/// - [blockId] :  The initial block number. Default: 1.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
CipherMAC chacha20poly1305(
  List<int> message,
  List<int> key, {
  List<int>? mac,
  List<int>? nonce,
  List<int>? aad,
  int blockId = 1,
}) =>
    ChaCha20Poly1305(ChaCha20(key)).convert(
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
/// - [key] : Either 16 or 32 bytes key.
/// - [nonce] : Either 8 or 12 bytes nonce.
/// - [aad] : Additional authenticated data.
/// - [mac] : A 128-bit or 16-bytes long authentication tag for verification.
/// - [blockId] :  The initial block number. Default: 1.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
AsyncCipherMAC chacha20poly1305Stream(
  Stream<int> stream,
  List<int> key, {
  Future<HashDigest>? mac,
  List<int>? nonce,
  List<int>? aad,
  int blockId = 1,
}) =>
    ChaCha20Poly1305(ChaCha20(key)).stream(
      stream,
      nonce: nonce,
      mac: mac,
      aad: aad,
      blockId: blockId,
    );
