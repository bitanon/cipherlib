// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/chacha20.dart';

export 'algorithms/chacha20.dart' show ChaCha20;

/// Apply [ChaCha20] cipher with the follwing parameters:
///
/// - Arbitrary length plaintext [message] to transform.
/// - A 256-bit or 32-bytes long [key].
/// - (Optional) A 96-bit or 12-bytes long [nonce].
/// - (Optional) The initial block number as [blockCount]. Default: 1.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Uint8List chacha20(
  List<int> message,
  List<int> key, [
  List<int>? nonce,
  int blockCount = 1,
]) =>
    ChaCha20(key).convert(
      message,
      nonce: nonce,
      blockCount: blockCount,
    );

/// Apply [ChaCha20] cipher with the follwing parameters:
///
/// - Plaintext message [stream] to transform.
/// - A 256-bit or 32-bytes long [key].
/// - (Optional) A 96-bit or 12-bytes long [nonce].
/// - (Optional) The initial block number as [blockCount]. Default: 1.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Stream<int> chacha20Pipe(
  Stream<int> stream,
  List<int> key, [
  List<int>? nonce,
  int blockCount = 1,
]) =>
    ChaCha20(key).pipe(
      stream,
      nonce: nonce,
      blockCount: blockCount,
    );
