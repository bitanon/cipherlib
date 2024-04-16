// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/auth_cipher.dart';
import 'package:hashlib/hashlib.dart' show HashDigest, Poly1305;

/// [Poly1305] is an authentication algorithm used for verifying the integrity
/// of messages. It generates a short, fixed-length tag based on a secret key
/// and the message, providing assurance that the message has not been
/// tampered with.
///
/// This is intended to be used as a mixin with the original ChaCha20 or Salsa20
/// algorithms to generate message digests.
abstract class Poly1305Authenticator implements Authenticator {
  // Generate a 32-bytes long One-Time-Key for Poly1305 digest
  Uint8List generateOTK([List<int>? nonce]);

  @override
  HashDigest digest(
    List<int> message, {
    List<int>? nonce,
    List<int>? aad,
  }) {
    // create key
    var otk = generateOTK(nonce);

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
