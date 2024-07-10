// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'cipher.dart';

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

  /// Encrypts the [stream] using the algorithm
  @pragma('vm:prefer-inline')
  Stream<int> encryptStream(Stream<int> stream) => encryptor.stream(stream);

  /// Decrypts the [stream] using the algorithm
  @pragma('vm:prefer-inline')
  Stream<int> decryptStream(Stream<int> stream) => decryptor.stream(stream);

  /// Encrypts the [message] using the algorithm
  @pragma('vm:prefer-inline')
  Uint8List encryptString(String message, [Encoding? encoding]) =>
      encryptor.convert(
        encoding == null ? message.codeUnits : encoding.encode(message),
      );

  /// Decrypts the [message] using the algorithm
  @pragma('vm:prefer-inline')
  Uint8List decryptString(String message, [Encoding? encoding]) =>
      decryptor.convert(
        encoding == null ? message.codeUnits : encoding.encode(message),
      );
}
