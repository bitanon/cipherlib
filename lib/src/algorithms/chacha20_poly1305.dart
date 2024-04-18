// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:cipherlib/src/core/authenticator.dart';
import 'package:cipherlib/src/core/chunk_stream.dart';
import 'package:hashlib/hashlib.dart' show HashDigest;

import 'chacha20.dart';
import 'poly1305.dart';

/// ChaCha20-Poly1305 is a cryptographic algorithm combining the [ChaCha20]
/// stream cipher for encryption andthe [Poly1305Mac] for generating message
/// authentication code.
/// It provides both confidentiality and integrity protection, making it a
/// popular choice for secure communication protocols like TLS.
///
/// This implementation is based on the [RFC-8439][rfc]
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc8439.html
class ChaCha20Poly1305 extends ChaCha20 with Authenticator {
  @override
  String get name => "${super.name}/Poly1305";

  const ChaCha20Poly1305(List<int> key) : super(key);

  /// Generate One-Time-Key for Poly1305
  @pragma('vm:prefer-inline')
  Uint8List _generateOTK([List<int>? nonce]) => convert(
        Uint8List(32),
        nonce: nonce,
        blockId: 0,
      );

  @override
  HashDigest digest(
    List<int> message, {
    List<int>? nonce,
    List<int>? aad,
  }) =>
      Poly1305Mac(
        _generateOTK(nonce),
        aad: aad,
      ).convert(message);

  @override
  bool verify(
    List<int> message,
    List<int> mac, {
    List<int>? nonce,
    List<int>? aad,
  }) =>
      digest(
        message,
        nonce: nonce,
        aad: aad,
      ).isEqual(mac);

  @override
  CipherMAC convertWithDigest(
    List<int> message, {
    List<int>? mac,
    List<int>? nonce,
    List<int>? aad,
    int blockId = 1,
  }) {
    var otk = _generateOTK(nonce);
    if (mac != null) {
      var digest = Poly1305Mac(otk, aad: aad).convert(message);
      if (!digest.isEqual(mac)) {
        throw StateError('Invalid MAC');
      }
    }
    var cipher = convert(
      message,
      nonce: nonce,
      blockId: blockId,
    );
    var digest = Poly1305Mac(otk, aad: aad).convert(cipher);
    return CipherMAC(cipher, digest);
  }

  @override
  AsyncCipherMAC streamWithDigest(
    Stream<int> stream, {
    Future<HashDigest>? mac,
    List<int>? nonce,
    List<int>? aad,
    int blockId = 1,
  }) {
    var controller = StreamController<int>(sync: true);
    return AsyncCipherMAC(
      controller.stream,
      $buildDigest(
        controller,
        stream,
        mac: mac,
        nonce: nonce,
        aad: aad,
        blockId: blockId,
      ),
    );
  }

  Future<HashDigest> $buildDigest(
    StreamController<int> controller,
    Stream<int> stream, {
    Future<HashDigest>? mac,
    List<int>? nonce,
    List<int>? aad,
    int blockId = 1,
  }) async {
    var otk = _generateOTK(nonce);
    var sink = mac != null ? Poly1305Mac(otk, aad: aad).createSink() : null;
    // create digest sink for cipher
    var cipherSink = Poly1305Mac(otk, aad: aad).createSink();
    // cipher stream
    var it = generate(nonce, blockId).iterator;
    await for (var buffer in asChunkedStream(4096, stream)) {
      sink?.add(buffer);
      for (int p = 0; p < buffer.length; ++p) {
        it.moveNext();
        buffer[p] ^= it.current;
        controller.add(buffer[p]);
      }
      cipherSink.add(buffer);
    }
    controller.close();
    // message digest
    if (sink != null && mac != null) {
      if (!sink.digest().isEqual(await mac)) {
        throw StateError('Invalid MAC');
      }
    }
    // cipher digest
    return cipherSink.digest();
  }
}
