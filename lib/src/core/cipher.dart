// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

/// Template for encryption and decryption algorithms.
abstract class Cipher {
  const Cipher();

  /// Name of the Cipher
  String get name;
}

/// Template for Symmetric Ciphers that uses the same operation for both
/// encryption and decryption.
abstract class SymmetricCipher extends Cipher
    implements StreamTransformer<int, int> {
  const SymmetricCipher();

  /// Transforms the [message].
  Uint8List convert(List<int> message);

  @override
  Stream<int> bind(Stream<int> stream);

  @override
  StreamTransformer<RS, RT> cast<RS, RT>() =>
      StreamTransformer.castFrom<int, int, RS, RT>(this);
}

/// Template for Asymmetric Ciphers that uses different operations for
/// encryption and decryption.
abstract class AsymmetricCipher extends Cipher {
  const AsymmetricCipher();

  /// The cipher algorithm for encryption.
  SymmetricCipher get encryptor;

  /// The cipher algorithm for decryption.
  SymmetricCipher get decryptor;

  /// Encrypts the [message] using the algorithm
  Uint8List encrypt(List<int> message) => encryptor.convert(message);

  /// Decrypts the [cipher] using the algorithm
  Uint8List decrypt(List<int> cipher) => decryptor.convert(cipher);

  /// Encrypts the [stream] using the algorithm
  Stream<int> encryptStream(Stream<int> stream) => encryptor.bind(stream);

  /// Decrypts the [stream] using the algorithm
  Stream<int> decryptStream(Stream<int> stream) => decryptor.bind(stream);
}
