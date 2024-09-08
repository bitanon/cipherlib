// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';
import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:hashlib/hashlib.dart'
    show HashDigest, HashDigestSink, MACHashBase;

/// The result fromo AEAD ciphers
class AEADResult {
  /// The output message
  final Uint8List data;

  /// The message authentication code
  final HashDigest tag;

  const AEADResult._({
    required this.tag,
    required this.data,
  });

  /// Returns whether the generated [tag] (message authentication code) is
  /// equal to the provided tag [digest].
  bool verify(List<int>? digest) => tag.isEqual(digest);

  /// Creates a new instance of AEADResult with IV parameter
  AEADResultWithIV withIV(Uint8List iv) =>
      AEADResultWithIV._(tag: tag, data: data, iv: iv);
}

class AEADResultWithIV extends AEADResult {
  /// The IV, available if and only if cipher does supports it.
  final Uint8List iv;

  const AEADResultWithIV._({
    required this.iv,
    required HashDigest tag,
    required Uint8List data,
  }) : super._(tag: tag, data: data);
}

/// Extends the base [AEADCipherSink] to generate message digest for cipher
/// algorithms.
class AEADCipherSink<C extends CipherSink, H extends HashDigestSink>
    extends CipherSink {
  final H _sink;
  final C _cipher;
  final List<int>? _aad;
  int _dataLength = 0;
  bool _verifyMode;

  AEADCipherSink(
    this._cipher,
    this._sink, [
    this._aad,
    this._verifyMode = false,
  ]) {
    _cipher.reset();
    if (_aad != null) {
      _sink.add(_aad!);
      // pad with zero
      int n = _aad!.length;
      if (n & 15 != 0) {
        _sink.add(Uint8List(16 - (n & 15)));
      }
    }
  }

  /// The length of generated hash in bytes
  int get macLength => _sink.hashLength;

  @override
  bool get closed => _sink.closed || _cipher.closed;

  @override
  void reset([bool forVerification = false]) {
    _sink.reset();
    _cipher.reset();
    _verifyMode = forVerification;
  }

  /// Finalizes the message-digest and returns a [HashDigest].
  ///
  /// Throws [StateError] if this sink is not closed before generating digest.
  HashDigest digest() {
    if (!closed) {
      close();
    }
    return _sink.digest();
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
      _dataLength += end - start;
      _sink.add(data, start, end);
    } else {
      _dataLength += cipher.length;
      _sink.add(cipher);
    }
    if (last) {
      // pad with zero
      if (_dataLength & 15 != 0) {
        _sink.add(Uint8List(16 - (_dataLength & 15)));
      }
      int n = _aad?.length ?? 0;
      _sink.add([
        n,
        n >>> 8,
        n >>> 16,
        n >>> 24,
        n >>> 32,
        n >>> 40,
        n >>> 48,
        n >>> 56,
        _dataLength,
        _dataLength >>> 8,
        _dataLength >>> 16,
        _dataLength >>> 24,
        _dataLength >>> 32,
        _dataLength >>> 40,
        _dataLength >>> 48,
        _dataLength >>> 56,
      ]);
    }
    return cipher;
  }
}

/// Provides support for AEAD (Authenticated Encryption with Associated Data) to
/// the any [Cipher] with any MAC algorithm.
abstract class AEADCipher<C extends Cipher, M extends MACHashBase>
    extends StreamCipherBase {
  /// The MAC generator used by this AEAD construction
  final M mac;

  /// The cipher used by this AEAD construction
  final C cipher;

  /// Additional authenticated data (optional)
  final List<int>? aad;

  @override
  String get name => '${cipher.name}/${mac.name}';

  const AEADCipher(
    this.cipher,
    this.mac, [
    this.aad,
  ]);

  AEADCipherSink createSink([
    bool verifyMode = false,
  ]) =>
      AEADCipherSink(
        cipher.createSink(),
        mac.createSink(),
        aad,
        verifyMode,
      );

  /// Transforms the [message] with an authentication tag.
  @pragma('vm:prefer-inline')
  AEADResult convert(List<int> message) {
    var sink = createSink();
    var cipher = sink.add(message, 0, null, true);
    var digest = sink.digest();
    return AEADResult._(
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
