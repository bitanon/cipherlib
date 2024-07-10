// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show fillRandom;

import 'cipher.dart';
import 'collate_cipher.dart';

/// Template for Ciphers accepting a random initialization vector or salt
abstract class SaltedCipher extends Cipher {
  /// The salt or initialization vector
  final Uint8List iv;

  /// Creates the cipher with a random initialization vector
  const SaltedCipher(this.iv);

  /// Replaces current IV with a new random one
  @pragma('vm:prefer-inline')
  void resetIV() => fillRandom(iv.buffer);
}

/// Template for Cipher algorithm accepting an IV (Initialization Vector) which
/// does not use the same logic for encryption and decryption.
abstract class SaltedCollateCipher<E extends SaltedCipher,
    D extends SaltedCipher> extends CollateCipher<E, D> {
  const SaltedCollateCipher();

  /// IV for the cipher
  Uint8List get iv => encryptor.iv;

  /// Replaces current IV with a new random one
  @pragma('vm:prefer-inline')
  void resetIV() => fillRandom(iv.buffer);
}
