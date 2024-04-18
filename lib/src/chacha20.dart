// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/chacha20.dart';

export 'algorithms/chacha20.dart' show ChaCha20;

/// Apply [ChaCha20] cipher with the follwing parameters:
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : A 32-bytes long key.
/// - [nonce] : A 12-bytes long nonce. Deafult: 0
/// - [blockId] :  The initial block number. Default: 1.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Uint8List chacha20(
  List<int> message,
  List<int> key, [
  List<int>? nonce,
  int blockId = 1,
]) =>
    ChaCha20(key).convert(
      message,
      nonce: nonce,
      blockId: blockId,
    );

/// Apply [ChaCha20] cipher with the follwing parameters:
///
/// Parameters:
/// - [stream] : arbitrary length plain-text.
/// - [key] : A 32-bytes long key.
/// - [nonce] : A 12-bytes long nonce. Deafult: 0
/// - [blockId] :  The initial block number. Default: 1.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Stream<int> chacha20Stream(
  Stream<int> stream,
  List<int> key, [
  List<int>? nonce,
  int blockId = 1,
]) =>
    ChaCha20(key).bind(
      stream,
      nonce: nonce,
      blockId: blockId,
    );
