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
class ChaCha20Poly1305 implements Authenticator {
  final ChaCha20 _algo;

  const ChaCha20Poly1305(this._algo);

  @override
  String get name => "${_algo.name}/Poly1305";

  /// Generate One-Time-Key for Poly1305
  @pragma('vm:prefer-inline')
  Uint8List _generateOTK(List<int> nonce) => _algo.convert(
        Uint8List(32),
        nonce: nonce,
        blockId: 0,
      );

  @override
  @pragma('vm:prefer-inline')
  HashDigest digest(
    List<int> message, {
    required List<int> nonce,
    List<int>? aad,
  }) =>
      Poly1305Mac(
        _generateOTK(nonce),
        aad: aad,
      ).convert(message);

  @override
  @pragma('vm:prefer-inline')
  bool verify(
    List<int> message, {
    required List<int> mac,
    required List<int> nonce,
    List<int>? aad,
  }) =>
      digest(
        message,
        nonce: nonce,
        aad: aad,
      ).isEqual(mac);

  @override
  CipherMAC convert(
    List<int> message, {
    List<int>? mac,
    List<int>? nonce,
    List<int>? aad,
    int blockId = 1,
  }) {
    var nonce8 = nonce == null
        ? Uint8List(12)
        : nonce is Uint8List
            ? nonce
            : Uint8List.fromList(nonce);
    var otk = _generateOTK(nonce8);
    if (mac != null) {
      var digest = Poly1305Mac(otk, aad: aad).convert(message);
      if (!digest.isEqual(mac)) {
        throw StateError('Invalid MAC');
      }
    }
    var cipher = _algo.convert(
      message,
      nonce: nonce,
      blockId: blockId,
    );
    var digest = Poly1305Mac(otk, aad: aad).convert(cipher);
    return CipherMAC(cipher, digest);
  }

  @override
  AsyncCipherMAC stream(
    Stream<int> stream, {
    Future<HashDigest>? mac,
    List<int>? nonce,
    List<int>? aad,
    int blockId = 1,
  }) {
    var controller = StreamController<int>(sync: true);
    return AsyncCipherMAC(
      controller.stream,
      _streamDigest(
        controller,
        stream,
        mac: mac,
        nonce: nonce,
        aad: aad,
        blockId: blockId,
      ),
    );
  }

  Future<HashDigest> _streamDigest(
    StreamController<int> controller,
    Stream<int> stream, {
    Future<HashDigest>? mac,
    List<int>? nonce,
    List<int>? aad,
    int blockId = 1,
  }) async {
    var nonce8 = nonce == null
        ? Uint8List(12)
        : nonce is Uint8List
            ? nonce
            : Uint8List.fromList(nonce);
    var otk = _generateOTK(nonce8);
    var sink = mac != null ? Poly1305Mac(otk, aad: aad).createSink() : null;
    // create digest sink for cipher
    var cipherSink = Poly1305Mac(otk, aad: aad).createSink();
    // cipher stream
    await for (var buffer in asChunkedStream(8192, stream)) {
      sink?.add(buffer);
      var block = _algo.rounds(buffer.length, nonce8, blockId);
      blockId += 128;
      for (int p = 0; p < buffer.length; ++p) {
        block[p] ^= buffer[p];
        controller.add(block[p]);
      }
      cipherSink.add(block);
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

extension ChaCha20ExtensionForPoly1305 on ChaCha20 {
  @pragma('vm:prefer-inline')
  ChaCha20Poly1305 poly1305() => ChaCha20Poly1305(this);
}
