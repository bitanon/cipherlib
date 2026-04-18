// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async' show Stream, StreamTransformer;
import 'dart:convert' show Encoding;
import 'dart:typed_data' show Uint8List;

import 'package:hashlib/random.dart' show fillRandom;

import '../utils/chunk_stream.dart';

/// Template for all Cipher algorithms in this package
abstract class CipherBase {
  const CipherBase();

  /// The name of the algorithm
  String get name;
}

/// Template for Cipher algorithm that uses the same logic for
/// both encryption and decryption.
abstract class Cipher
    implements CipherBase, StreamTransformer<List<int>, Uint8List> {
  const Cipher();

  /// Transforms the [message].
  Uint8List convert(List<int> message);

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) => stream.map(convert);

  @override
  StreamTransformer<RS, RT> cast<RS, RT>() {
    throw UnsupportedError('StreamCipherBase does not allow casting');
  }

  /// Transforms the [stream]
  Stream<int> stream(Stream<int> stream, [int chunkSize = 1024]) async* {
    final chunk = asChunkedStream(chunkSize, stream);
    await for (var data in bind(chunk)) {
      for (var byte in data) {
        yield byte;
      }
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

/// Template for Cipher algorithm which does not use the same logic for
/// encryption and decryption.
abstract class CollateCipher<E extends Cipher, D extends Cipher>
    implements CipherBase {
  const CollateCipher();

  /// The cipher algorithm for encryption.
  E get encryptor;

  /// The cipher algorithm for decryption.
  D get decryptor;

  /// Encrypts the [message] using the algorithm
  @pragma('vm:prefer-inline')
  Uint8List encrypt(List<int> message) => encryptor.convert(message);

  /// Decrypts the [message] using the algorithm
  @pragma('vm:prefer-inline')
  Uint8List decrypt(List<int> message) => decryptor.convert(message);

  /// Encrypts the [message] using the algorithm
  @pragma('vm:prefer-inline')
  Uint8List encryptString(String message, [Encoding? encoding]) =>
      encrypt(encoding == null ? message.codeUnits : encoding.encode(message));

  /// Decrypts the [message] using the algorithm
  @pragma('vm:prefer-inline')
  Uint8List decryptString(String message, [Encoding? encoding]) =>
      decrypt(encoding == null ? message.codeUnits : encoding.encode(message));
}
