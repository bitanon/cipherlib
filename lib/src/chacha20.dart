// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'algorithms/chacha20.dart';

export 'algorithms/chacha20.dart' show ChaCha20;

/// Apply [ChaCha20] cipher to the [message] using the [key] and [nonce].
///
/// Both the encryption and decryption can be done using this same method.
Uint8List chacha20(
  List<int> message,
  List<int> key, [
  List<int>? nonce,
]) {
  return ChaCha20(
    key: key,
    nonce: nonce ?? Uint8List(12),
  ).convert(message);
}

/// Apply [ChaCha20] cipher to the message [stream] using the [key] and [nonce].
///
/// Both the encryption and decryption can be done using this same method.
Stream<int> chacha20Pipe(
  Stream<int> stream,
  List<int> key, [
  List<int>? nonce,
]) {
  return ChaCha20(
    key: key,
    nonce: nonce ?? Uint8List(12),
  ).pipe(stream);
}
