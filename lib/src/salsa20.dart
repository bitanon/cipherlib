// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/salsa20.dart';

export 'algorithms/salsa20.dart' show Salsa20;

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
  List<int> key, [
  List<int>? nonce,
]) =>
    Salsa20(key).convert(
      message,
      nonce: nonce,
    );

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
  List<int> key, [
  List<int>? nonce,
]) =>
    Salsa20(key).stream(
      stream,
      nonce: nonce,
    );
