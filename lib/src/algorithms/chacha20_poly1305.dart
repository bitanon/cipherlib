// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/auth_cipher.dart';
import 'package:hashlib/hashlib.dart' show HashDigest, Poly1305;

import 'chacha20.dart';

class ChaCha20Poly1305 extends ChaCha20 with Authenticator {
  @override
  String get name => "ChaCha20/Poly1305";

  ChaCha20Poly1305(List<int> key) : super(key);

  @override
  HashDigest digest(
    List<int> message, {
    List<int>? nonce,
    List<int>? aad,
  }) {
    // create key
    var otk = convert(
      Uint8List(32),
      nonce: nonce,
      blockCount: 0,
    );

    // create sink
    var sink = Poly1305(otk).createSink();

    // add AAD
    int aadLength = aad?.length ?? 0;
    if (aad != null && aadLength > 0) {
      sink.add(aad);
      sink.add(Uint8List(16 - (aadLength & 15)));
    }

    // add cipher text
    int messageLength = message.length;
    if (messageLength > 0) {
      sink.add(message);
      sink.add(Uint8List(16 - (messageLength & 15)));
    }

    // add lengths
    sink.add(Uint32List.fromList([
      aadLength,
      aadLength >>> 32,
      messageLength,
      messageLength >>> 32,
    ]).buffer.asUint8List());

    return sink.digest();
  }

  @override
  bool verify(
    List<int> message,
    List<int> tag, {
    List<int>? nonce,
    List<int>? aad,
  }) {
    var current = digest(
      message,
      nonce: nonce,
      aad: aad,
    );
    return current.isEqual(tag);
  }
}
