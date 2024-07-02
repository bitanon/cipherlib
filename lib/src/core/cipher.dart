// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:cipherlib/src/core/utils.dart';
import 'package:hashlib/hashlib.dart' show HashDigest;

const int _defaultBufferSize = 1024;

abstract class CipherBase {
  const CipherBase();

  /// The name of the algorithm
  String get name;
}

/// Template for Cipher algorithm sink.
abstract class CipherSink implements Sink<List<int>> {
  const CipherSink();

  /// Adds [data] to the sink to returns the converted result.
  ///
  /// Throws [StateError] if called after a call to [close],
  /// or a call to [add] with [last] set to true.
  @override
  Uint8List add(List<int> data, [bool last = false]);

  /// Closes the sink and returns the last converted result.
  ///
  /// Same as calling `add([], true)`.
  @override
  @pragma('vm:prefer-inline')
  Uint8List close() => add([], true);
}

/// Template for Cipher algorithm that uses the same logic for
/// both encryption and decryption.
abstract class Cipher extends CipherBase
    implements StreamTransformer<List<int>, Uint8List> {
  const Cipher();

  /// Creates a sink for the algorithm
  CipherSink createSink();

  /// Transforms the [message].
  @pragma('vm:prefer-inline')
  Uint8List convert(List<int> message) => createSink().add(message, true);

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) async* {
    var sink = createSink();
    List<int>? cache;
    await for (var data in stream) {
      if (cache != null) {
        yield sink.add(cache);
      }
      cache = data;
    }
    yield sink.add(cache ?? [], true);
  }

  /// Transforms the [stream]
  Stream<int> stream(Stream<int> stream) async* {
    int p = 0;
    var sink = createSink();
    var buffer = Uint8List(_defaultBufferSize);
    await for (var x in stream) {
      buffer[p++] = x;
      if (p == buffer.length) {
        for (var e in sink.add(buffer)) {
          yield e;
        }
        p = 0;
      }
    }
    List<int> rest = (p == 0) ? [] : Uint8List.view(buffer.buffer, 0, p);
    for (var e in sink.add(rest, true)) {
      yield e;
    }
  }

  @override
  StreamTransformer<RS, RT> cast<RS, RT>() =>
      StreamTransformer.castFrom<List<int>, Uint8List, RS, RT>(this);
}

/// Template for Cipher algorithm which does not use the same logic for
/// both encryption and decryption.
abstract class CollateCipher implements CipherBase {
  const CollateCipher();

  /// The cipher algorithm for encryption.
  Cipher get encryptor;

  /// The cipher algorithm for decryption.
  Cipher get decryptor;

  /// Encrypts the [message] using the algorithm
  @pragma('vm:prefer-inline')
  Uint8List encrypt(List<int> message) => encryptor.convert(message);

  /// Decrypts the [message] using the algorithm
  @pragma('vm:prefer-inline')
  Uint8List decrypt(List<int> message) => decryptor.convert(message);

  /// Encrypts the [stream] using the algorithm
  @pragma('vm:prefer-inline')
  Stream<int> encryptStream(Stream<int> stream) => encryptor.stream(stream);

  /// Decrypts the [stream] using the algorithm
  @pragma('vm:prefer-inline')
  Stream<int> decryptStream(Stream<int> stream) => decryptor.stream(stream);
}

/// Mixin for ciphers with AEAD support
abstract class AEADCipher implements CipherBase {
  /// Generates the authentication tag for the [message].
  @pragma('vm:prefer-inline')
  HashDigest digest(List<int> message) => verify(message);

  /// Generates the authentication tag for the [stream].
  @pragma('vm:prefer-inline')
  Future<HashDigest> digestStream(Stream<int> stream) => verifyStream(stream);

  /// Generates the authentication tag for the buffered [stream].
  @pragma('vm:prefer-inline')
  Future<HashDigest> digestBufferedStream(Stream<List<int>> stream) =>
      verifyBufferedStream(stream);

  /// Verify the [message] against the authentication code [mac],
  /// and throws an [AssertionError] on match failure.
  ///
  /// If [mac] is absent it returns the digest only without any verification.
  HashDigest verify(
    List<int> message, [
    List<int>? mac,
  ]);

  /// Verify the byte [stream] against the authentication code [mac],
  /// and throws an [AssertionError] on match failure.
  ///
  /// If [mac] is absent it returns the digest only without any verification.
  @pragma('vm:prefer-inline')
  Future<HashDigest> verifyStream(
    Stream<int> stream, [
    Future<List<int>>? mac,
  ]) =>
      verifyBufferedStream(asBufferedStream(stream, _defaultBufferSize), mac);

  /// Verify the buffered byte [stream] against the authentication code [mac],
  /// and throws an [AssertionError] on match failure.
  ///
  /// If [mac] is absent it returns the digest only without any verification.
  @pragma('vm:prefer-inline')
  Future<HashDigest> verifyBufferedStream(
    Stream<List<int>> stream, [
    Future<List<int>>? mac,
  ]);
}
