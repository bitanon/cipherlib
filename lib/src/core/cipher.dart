// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async' show StreamTransformer;
import 'dart:convert' show Encoding;
import 'dart:typed_data' show Uint8List;

import 'package:hashlib/random.dart' show fillRandom;

// ------------------------------------------------------------
// CipherBase
// ------------------------------------------------------------
/// Template for all Cipher algorithms in this package
abstract class CipherBase {
  const CipherBase();

  /// The name of the algorithm
  String get name;
}

// ------------------------------------------------------------
// SaltedCipher
// ------------------------------------------------------------

/// Mixin to use a random initialization vector or salt with the Cipher
mixin SaltedCipher on CipherBase {
  /// The salt or initialization vector
  Uint8List get iv;

  /// Replaces current IV with a new random one
  @pragma('vm:prefer-inline')
  void resetIV() => fillRandom(
        iv.buffer,
        start: iv.offsetInBytes,
        length: iv.lengthInBytes,
      );
}

// ------------------------------------------------------------
// Cipher
// ------------------------------------------------------------
/// Template for symmetric cipher algorithms that uses the same logic for
/// both encryption and decryption.
abstract class Cipher implements CipherBase {
  const Cipher();

  /// Transforms the [message] of bytes using the algorithm.
  Uint8List convert(List<int> message);
}

// ------------------------------------------------------------
// StreamCipher
// ------------------------------------------------------------

/// Template for Cipher algorithm that uses the same logic for
/// both encryption and decryption.
abstract class StreamCipher
    implements Cipher, StreamTransformer<List<int>, Uint8List> {
  const StreamCipher();

  /// Transform the [stream] of chunks of message bytes using the algorithm.
  @override
  Stream<Uint8List> bind(Stream<List<int>> stream);

  @override
  StreamTransformer<RS, RT> cast<RS, RT>() {
    throw UnsupportedError('StreamCipher does not allow casting');
  }
}

// ------------------------------------------------------------
// CipherPair
// ------------------------------------------------------------

/// Template for symmetric cipher algorithms which does not use the same logic
/// for both encryption and decryption.
abstract class CipherPair<E extends Cipher, D extends Cipher>
    implements CipherBase {
  const CipherPair();

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

/// Template for symmetric cipher algorithms which does not use the same logic
/// for both encryption and decryption.
abstract class StreamCipherPair<E extends StreamCipher, D extends StreamCipher>
    extends CipherPair<E, D> {
  const StreamCipherPair();
}
