// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/chacha20.dart';

export 'algorithms/chacha20.dart' show ChaCha20, ChaCha20Sink;

/// Apply [ChaCha20] cipher with the follwing parameters:
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : Either 16 or 32 bytes key.
/// - [nonce] : Either 8 or 12 bytes nonce.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Uint8List chacha20(
  List<int> message,
  List<int> key, {
  List<int>? nonce,
  int counter = 1,
}) =>
    ChaCha20.fromList(
      key,
      nonce ?? Uint8List(12),
      counter,
    ).convert(message);

/// Apply [ChaCha20] cipher with the follwing parameters:
///
/// Parameters:
/// - [stream] : arbitrary length plain-text.
/// - [key] : Either 16 or 32 bytes key.
/// - [nonce] : Either 8 or 12 bytes nonce.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Stream<int> chacha20Stream(
  Stream<int> stream,
  List<int> key, {
  List<int>? nonce,
  int counter = 1,
}) =>
    ChaCha20.fromList(
      key,
      nonce ?? Uint8List(12),
      counter,
    ).stream(stream);
