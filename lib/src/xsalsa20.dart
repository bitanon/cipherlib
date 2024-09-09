// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/salsa20.dart';
import 'package:cipherlib/src/utils/nonce.dart';

export 'algorithms/salsa20.dart' show XSalsa20;

/// Apply [XSalsa20] cipher with the follwing parameters:
///
/// Parameters:
/// - [message] : arbitrary length plain-text.
/// - [key] : 32 bytes key.
/// - [nonce] : 24 bytes nonce. (Default: random)
/// - [counter] : 64-bit counter. (Default: 0)
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Uint8List xsalsa20(
  List<int> message,
  List<int> key, {
  List<int>? nonce,
  Nonce64? counter,
}) =>
    XSalsa20(key, nonce, counter).convert(message);

/// Apply [XSalsa20] cipher with the follwing parameters:
///
/// Parameters:
/// - [stream] : arbitrary length plain-text.
/// - [key] : 32 bytes key.
/// - [nonce] : 24 bytes nonce. (Default: random)
/// - [counter] : 64-bit counter. (Default: 0)
///
/// Both the encryption and decryption can be done using this same method.
@pragma('vm:prefer-inline')
Stream<int> xsalsa20Stream(
  Stream<int> stream,
  List<int> key, {
  List<int>? nonce,
  Nonce64? counter,
}) =>
    XSalsa20(key, nonce, counter).stream(stream);
