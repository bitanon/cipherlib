// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';
import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:hashlib/hashlib.dart'
    show HashDigest, HashDigestSink, MACHashBase;

/// The result from AEAD ciphers
class AEADResult {
  /// The output message
  final Uint8List data;

  /// The message authentication code
  final HashDigest tag;

  const AEADResult._(this.data, this.tag);

  /// Returns whether the generated [tag] (message authentication code) is
  /// equal to the provided tag [digest].
  bool verify(List<int>? digest) => tag.isEqual(digest);

  /// Creates a new instance of AEADResult with IV parameter
  AEADResultWithIV withIV(Uint8List iv) => AEADResultWithIV._(data, tag, iv);
}

/// The result from AEAD ciphers having an IV or nonce
class AEADResultWithIV extends AEADResult {
  /// The nonce or initialization vector
  final Uint8List iv;

  const AEADResultWithIV._(
    Uint8List data,
    HashDigest tag,
    this.iv,
  ) : super._(data, tag);
}

/// Extends the base [AEADCipherSink] to generate message digest for cipher
/// algorithms.
class AEADCipherSink<C extends CipherSink, H extends HashDigestSink>
    implements CipherSink {
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

  @override
  Uint8List add(
    List<int> data, [
    bool last = false,
    int start = 0,
    int? end,
  ]) {
    end ??= data.length;
    var cipher = _cipher.add(data, last, start, end);
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

  @override
  Uint8List close() {
    final r = add([], true);
    _sink.close();
    return r;
  }

  /// Returns the current tag as [HashDigest] after sink is closed.
  ///
  /// Throws [StateError] if this sink is not closed before generating digest.
  HashDigest digest() {
    if (!closed) {
      throw StateError('The sink is not yet closed');
    }
    return _sink.digest();
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

  /// Creates a sink to process multiple input messages in chunks
  ///
  /// If [verifyMode] is true, the generated tag can only be used to verify
  /// the input message integrity. To get a tag for the input message itself,
  /// pass it as false.
  AEADCipherSink createSink([
    bool verifyMode = false,
  ]) =>
      AEADCipherSink(
        cipher.createSink(),
        mac.createSink(),
        aad,
        verifyMode,
      );

  /// Transforms the [message]. Alias for [sign].
  @pragma('vm:prefer-inline')
  Uint8List convert(List<int> message, [bool verifyMode = false]) =>
      createSink(verifyMode).add(message, true);

  /// Signs the [message] with an authentication tag.
  AEADResult sign(List<int> message) {
    var sink = createSink();
    var cipher = sink.add(message, true);
    var digest = sink.digest();
    return AEADResult._(cipher, digest);
  }

  /// Returns true if [message] can be verified with the authentication [tag].
  @pragma('vm:prefer-inline')
  bool verify(List<int> message, List<int> tag) =>
      (createSink(true)..add(message, true)).digest().isEqual(tag);

  @override
  Stream<Uint8List> bind(
    Stream<List<int>> stream, [
    Function(HashDigest tag)? onDigest,
    bool verifyMode = false,
  ]) async* {
    var sink = createSink(verifyMode);
    List<int>? cache;
    await for (var data in stream) {
      if (cache != null) {
        yield sink.add(cache);
      }
      cache = data;
    }
    yield sink.add(cache ?? [], true);
    if (onDigest != null) {
      onDigest(sink.digest());
    }
  }

  @override
  Stream<int> stream(
    Stream<int> stream, [
    Function(HashDigest tag)? onDigest,
    bool verifyMode = false,
  ]) async* {
    int p = 0;
    var sink = createSink(verifyMode);
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
    for (var e in sink.add(chunk, true, 0, p)) {
      yield e;
    }
    if (onDigest != null) {
      onDigest(sink.digest());
    }
  }
}
