// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

/// A template for encryption and decryption algorithms.
abstract class Cipher {
  const Cipher();
}

/// A template for Symmetric Ciphers that use the same operation for both
/// encryption and decryption.
abstract class SymmetricCipher extends Cipher {
  const SymmetricCipher();

  /// Transforms the [message].
  Uint8List convert(List<int> message);

  /// Transforms the message [stream].
  Stream<int> pipe(Stream<int> stream);
}

/// A template for Asymmetric Ciphers that use different operations for
/// encryption and decryption.
abstract class AsymmetricCipher extends Cipher {
  const AsymmetricCipher();

  /// The cipher algorithm for encryption.
  SymmetricCipher get encryptor;

  /// The cipher algorithm for decryption.
  SymmetricCipher get decryptor;

  /// Transforms the plain text [message] into encrypted cipher code.
  Uint8List encrypt(List<int> message) => encryptor.convert(message);

  /// Transforms the encrypted cipher [code] back to the plain text.
  Uint8List decrypt(List<int> code) => decryptor.convert(code);
}
