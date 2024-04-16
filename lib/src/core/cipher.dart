// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

/// A template for encryption and decryption algorithms.
abstract class Cipher<T> {
  const Cipher();

  /// Name of the Cipher
  String get name;

  /// Transforms the plain text [message] into encrypted cipher code.
  T encrypt(List<int> message);

  /// Transforms the encrypted [cipher] code back to the plain text.
  T decrypt(List<int> cipher);
}

/// A template for Symmetric Ciphers that use the same operation for both
/// encryption and decryption.
abstract class SymmetricCipher extends Cipher<Uint8List> {
  final Uint8List key;

  const SymmetricCipher(this.key);

  /// Transforms the [message].
  Uint8List convert(List<int> message);

  /// Transforms the message [stream].
  Stream<int> pipe(Stream<int> stream);

  @override
  Uint8List encrypt(List<int> message) => convert(message);

  @override
  Uint8List decrypt(List<int> cipher) => convert(cipher);
}

/// A template for Asymmetric Ciphers that use different operations for
/// encryption and decryption.
abstract class AsymmetricCipher extends Cipher<Uint8List> {
  const AsymmetricCipher();

  /// The cipher algorithm for encryption.
  SymmetricCipher get encryptor;

  /// The cipher algorithm for decryption.
  SymmetricCipher get decryptor;

  @override
  Uint8List encrypt(List<int> message) => encryptor.convert(message);

  @override
  Uint8List decrypt(List<int> cipher) => decryptor.convert(cipher);
}
