// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/chacha20.dart';
import 'package:cipherlib/src/utils/nonce.dart';

export 'algorithms/chacha20.dart' show ChaCha20, ChaCha20Sink;

/// Apply [ChaCha20] cipher with the follwing parameters:
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : 16 or 32 bytes key.
/// - [nonce] : 8 or 12 bytes nonce.
/// - [counter] : 64-bit counter. (Default: 1)
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Uint8List chacha20(
  List<int> message,
  List<int> key, {
  List<int>? nonce,
  Nonce64? counter,
}) =>
    ChaCha20.fromList(
      key,
      nonce: nonce,
      counter: counter,
    ).convert(message);

/// Apply [ChaCha20] cipher with the follwing parameters:
///
/// Parameters:
/// - [stream] : arbitrary length plain-text.
/// - [key] : 16 or 32 bytes key.
/// - [nonce] : 8 or 12 bytes nonce.
/// - [counter] : 64-bit counter. (Default: 1)
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Stream<int> chacha20Stream(
  Stream<int> stream,
  List<int> key, {
  List<int>? nonce,
  Nonce64? counter,
}) =>
    ChaCha20.fromList(
      key,
      nonce: nonce,
      counter: counter,
    ).stream(stream);
