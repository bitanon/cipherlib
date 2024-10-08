// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:hashlib/random.dart' show fillRandom;

import 'cipher_sink.dart';

/// Template for all Cipher algorithms in this package
abstract class CipherBase {
  const CipherBase();

  /// The name of the algorithm
  String get name;
}

/// Template for Cipher algorithm that uses the same logic for
/// both encryption and decryption.
abstract class StreamCipherBase
    implements CipherBase, StreamTransformer<List<int>, Uint8List> {
  const StreamCipherBase();

  /// Transforms the [stream]
  Stream<int> stream(Stream<int> stream);

  /// Transforms the chunked [stream]
  @override
  Stream<Uint8List> bind(Stream<List<int>> stream);

  @override
  StreamTransformer<RS, RT> cast<RS, RT>() {
    throw UnsupportedError('StreamCipherBase does not allow casting');
  }
}

/// Template for Cipher algorithm that uses the same logic for
/// both encryption and decryption.
abstract class Cipher<S extends CipherSink> extends StreamCipherBase {
  const Cipher();

  /// Creates a sink for the algorithm
  S createSink();

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

  @override
  Stream<int> stream(Stream<int> stream) async* {
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
    for (var e in sink.add(chunk, true, 0, p)) {
      yield e;
    }
  }
}

/// Mixin to use a random initialization vector or salt with the Cipher
abstract class SaltedCipher implements CipherBase {
  /// The salt or initialization vector
  Uint8List get iv;

  /// Replaces current IV with a new random one
  @pragma('vm:prefer-inline')
  void resetIV() => fillRandom(iv.buffer);
}
