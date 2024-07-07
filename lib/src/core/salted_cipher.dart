// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show fillRandom;

import 'cipher.dart';

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
