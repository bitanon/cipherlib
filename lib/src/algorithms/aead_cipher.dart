// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';
import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:hashlib/hashlib.dart' show HashDigest, MACSinkBase, MACHashBase;

/// The result fromo AEAD ciphers
class AEADResult {
  /// The IV, available if and only if cipher does supports it.
  final Uint8List? iv;

  /// The output message
  final Uint8List data;

  /// The message authentication code
  final HashDigest tag;

  const AEADResult({
    this.iv,
    required this.tag,
    required this.data,
  });

  /// Returns whether the generated [tag] (message authentication code) is
  /// equal to the provided tag [digest].
  bool verify(List<int>? digest) => tag.isEqual(digest);

  /// Creates a new instance of AEADResult with IV parameter
  AEADResult withIV(Uint8List iv) => AEADResult(tag: tag, data: data, iv: iv);
}

/// Extends the base [AEADCipherSink] to generate message digest for cipher
/// algorithms.
class AEADCipherSink implements CipherSink, MACSinkBase {
  AEADCipherSink(
    this._cipher,
    this._hasher, [
    this._aad,
    this._verifyMode = false,
  ]) {
    _hasher.reset();
    _cipher.reset();
  }

  bool _verifyMode;
  int _messageLength = 0;
  final List<int>? _aad;
  final CipherSink _cipher;
  final MACSinkBase _hasher;

  @override
  int get hashLength => _hasher.hashLength;

  @override
  int get derivedKeyLength => _hasher.derivedKeyLength;

  @override
  bool get closed => _hasher.closed || _cipher.closed;

  @override
  void reset([bool asVerifyMode = false]) {
    _hasher.reset();
    _cipher.reset();
    _verifyMode = asVerifyMode;
  }

  @override
  Uint8List close() {
    return add([], 0, null, true);
  }

  @override
  HashDigest digest() {
    if (!closed) close();
    return _hasher.digest();
  }

  @override
  void init([List<int>? keypair]) {
    if (keypair != null) {
      _hasher.init(keypair);
    }
    if (_aad != null && _aad!.isNotEmpty) {
      _hasher.add(_aad!);
      // pad with zero
      int n = _aad!.length;
      if (n & 15 != 0) {
        _hasher.add(Uint8List(16 - (n & 15)));
      }
    }
    _messageLength = 0;
  }

  @override
  Uint8List add(
    List<int> data, [
    int start = 0,
    int? end,
    bool last = false,
  ]) {
    end ??= data.length;
    var cipher = _cipher.add(data, start, end, last);
    if (_verifyMode) {
      _messageLength += end - start;
      _hasher.add(data, start, end);
    } else {
      _messageLength += cipher.length;
      _hasher.add(cipher);
    }
    if (last) {
      // pad with zero
      if (_messageLength & 15 != 0) {
        _hasher.add(Uint8List(16 - (_messageLength & 15)));
      }
      int n = _aad?.length ?? 0;
      _hasher.add(Uint32List.fromList([
        n,
        n >>> 32,
        _messageLength,
        _messageLength >>> 32,
      ]).buffer.asUint8List());
    }
    return cipher;
  }
}

/// Provides support for AEAD (Authenticated Encryption with Associated Data) to
/// the any [Cipher] with any [MACHashBase] algorithm.
abstract class AEADCipher<C extends Cipher, M extends MACHashBase>
    extends StreamCipherBase {
  /// The cipher used by this AEAD construction
  final C cipher;

  /// The MAC generator used by this AEAD construction
  final M hasher;

  /// Additional authenticated data (optional)
  final List<int>? aad;

  @override
  String get name => '${cipher.name}/${hasher.name}';

  const AEADCipher(
    this.cipher,
    this.hasher, [
    this.aad,
  ]);

  AEADCipherSink createSink([
    bool verifyMode = false,
  ]) =>
      AEADCipherSink(
        cipher.createSink(),
        hasher.createSink(),
        aad,
        verifyMode,
      )..init();

  /// Transforms the [message] with an authentication tag.
  @pragma('vm:prefer-inline')
  AEADResult convert(List<int> message) {
    var sink = createSink();
    var cipher = sink.add(message, 0, null, true);
    var digest = sink.digest();
    return AEADResult(
      tag: digest,
      data: cipher,
    );
  }

  /// Returns true if [message] can be verified with the authentication [tag].
  bool verify(List<int> message, List<int> tag) {
    var sink = createSink(true);
    sink.add(message, 0, null, true);
    var digest = sink.digest();
    return digest.isEqual(tag);
  }

  @override
  Stream<Uint8List> bind(
    Stream<List<int>> stream, [
    Function(HashDigest tag)? onDigest,
  ]) async* {
    var sink = createSink();
    List<int>? cache;
    await for (var data in stream) {
      if (cache != null) {
        yield sink.add(cache);
      }
      cache = data;
    }
    yield sink.add(cache ?? [], 0, null, true);
    if (onDigest != null) {
      onDigest(sink.digest());
    }
  }

  @override
  Stream<int> stream(
    Stream<int> stream, [
    Function(HashDigest tag)? onDigest,
  ]) async* {
    int p = 0;
    var sink = createSink();
    var chunk = Uint8List(1024);
    await for (var x in stream) {
      chunk[p++] = x;
      if (p == chunk.length) {
        for (var e in sink.add(chunk)) {
          yield e;
        }
        p = 0;
      }
    }
    for (var e in sink.add(chunk, 0, p, true)) {
      yield e;
    }
    if (onDigest != null) {
      onDigest(sink.digest());
    }
  }
}
