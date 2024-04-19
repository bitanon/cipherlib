// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:cipherlib/src/core/authenticator.dart';
import 'package:cipherlib/src/core/chunk_stream.dart';
import 'package:hashlib/hashlib.dart' show HashDigest;

import 'poly1305.dart';
import 'salsa20.dart';

/// Salsa20-Poly1305 is a cryptographic algorithm combining the [Salsa20]
/// stream cipher for encryption and the [Poly1305Mac] for generating message
/// authentication code.
class Salsa20Poly1305 implements Authenticator {
  final Salsa20 _algo;

  const Salsa20Poly1305(this._algo);

  @override
  String get name => "${_algo.name}/Poly1305";

  /// Generate One-Time-Key for Poly1305
  @pragma('vm:prefer-inline')
  Uint8List _generateOTK(List<int> nonce) => _algo.convert(
        Uint8List(32),
        nonce: nonce,
      );

  @override
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
  }) {
    var nonce8 = nonce == null
        ? Uint8List(16)
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
      nonce: nonce8,
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
      ),
    );
  }

  Future<HashDigest> _streamDigest(
    StreamController<int> controller,
    Stream<int> stream, {
    Future<HashDigest>? mac,
    List<int>? nonce,
    List<int>? aad,
  }) async {
    var nonce8 = nonce == null
        ? Uint8List(16)
        : nonce is Uint8List
            ? nonce
            : Uint8List.fromList(nonce);
    var otk = _generateOTK(nonce8);
    var sink = mac != null ? Poly1305Mac(otk, aad: aad).createSink() : null;
    // create digest sink for cipher
    var cipherSink = Poly1305Mac(otk, aad: aad).createSink();
    // cipher stream
    int blockId = 1;
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

extension Salsa20ExtensionForPoly1305 on Salsa20 {
  @pragma('vm:prefer-inline')
  Salsa20Poly1305 poly1305() => Salsa20Poly1305(this);
}
