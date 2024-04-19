// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';

/// Template for encryption and decryption algorithms.
abstract class Cipher {
  const Cipher();

  /// Name of the Cipher
  String get name;
}

/// Template for Symmetric Ciphers that uses the same operation for both
/// encryption and decryption.
abstract class SymmetricCipher<R, SR> implements Cipher {
  const SymmetricCipher();

  /// Transforms the [message].
  R convert(List<int> message);

  /// Transforms the [stream]
  SR stream(Stream<int> stream);
}

/// Template for Asymmetric Ciphers that uses different operations for
/// encryption and decryption.
abstract class AsymmetricCipher<R, SR> implements Cipher {
  const AsymmetricCipher();

  /// The cipher algorithm for encryption.
  SymmetricCipher<R, SR> get encryptor;

  /// The cipher algorithm for decryption.
  SymmetricCipher<R, SR> get decryptor;

  /// Encrypts the [message] using the algorithm
  R encrypt(List<int> message) => encryptor.convert(message);

  /// Decrypts the [cipher] using the algorithm
  R decrypt(List<int> cipher) => decryptor.convert(cipher);

  /// Encrypts the [stream] using the algorithm
  SR encryptStream(Stream<int> stream) => encryptor.stream(stream);

  /// Decrypts the [stream] using the algorithm
  SR decryptStream(Stream<int> stream) => decryptor.stream(stream);
}
