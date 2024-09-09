// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/chacha20.dart';
import 'package:cipherlib/src/utils/nonce.dart';

export 'algorithms/chacha20.dart' show XChaCha20;

/// Apply [XChaCha20] cipher with the follwing parameters:
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : 32 bytes key.
/// - [nonce] : 24 bytes nonce. (Default: random)
/// - [counter] : 64-bit counter. (Default: 1)
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Uint8List xchacha20(
  List<int> message,
  List<int> key, {
  List<int>? nonce,
  Nonce64? counter,
}) =>
    XChaCha20(key, nonce, counter).convert(message);

/// Apply [XChaCha20] cipher with the follwing parameters:
///
/// Parameters:
/// - [stream] : arbitrary length plain-text.
/// - [key] : 32 bytes key.
/// - [nonce] : 24 bytes nonce. (Default: random)
/// - [counter] : 64-bit counter. (Default: 1)
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Stream<int> xchacha20Stream(
  Stream<int> stream,
  List<int> key, {
  List<int>? nonce,
  Nonce64? counter,
}) =>
    XChaCha20(key, nonce, counter).stream(stream);
