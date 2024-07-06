// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/salsa20.dart';

export 'algorithms/salsa20.dart' show Salsa20, Salsa20Sink;

/// Apply [Salsa20] cipher with the follwing parameters:
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : Either 16 or 32 bytes key.
/// - [nonce] : Either 8 or 16 bytes nonce.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Uint8List salsa20(
  List<int> message,
  List<int> key, {
  List<int>? nonce,
  int counter = 0,
}) =>
    Salsa20.fromList(
      key,
      nonce ?? Uint8List(16),
      counter,
    ).convert(message);

/// Apply [Salsa20] cipher with the follwing parameters:
///
/// Parameters:
/// - [stream] : arbitrary length plain-text.
/// - [key] : Either 16 or 32 bytes key.
/// - [nonce] : Either 8 or 16 bytes nonce.
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Stream<int> salsa20Stream(
  Stream<int> stream,
  List<int> key, {
  List<int>? nonce,
  int counter = 0,
}) =>
    Salsa20.fromList(
      key,
      nonce ?? Uint8List(16),
      counter,
    ).stream(stream);
