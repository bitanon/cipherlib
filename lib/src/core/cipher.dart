// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show fillRandom;

const int _defaultChunkSize = 1024;

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
    var chunk = Uint8List(_defaultChunkSize);
    await for (var x in stream) {
      chunk[p++] = x;
      if (p == chunk.length) {
        for (var e in sink.add(chunk)) {
          yield e;
        }
        p = 0;
      }
    }
    List<int> rest = (p == 0) ? [] : Uint8List.view(chunk.buffer, 0, p);
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

/// Template for Ciphers accepting a random salt
abstract class SaltedCipher extends Cipher {
  /// The salt or initialization vector
  final Uint8List salt;

  /// Creates the cipher with an initial salt value
  const SaltedCipher(this.salt);

  /// Replace the current salt with a new one
  @pragma('vm:prefer-inline')
  void resetSalt() => fillRandom(salt.buffer);
}
