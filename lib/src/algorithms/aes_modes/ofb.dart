// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../../core/aes.dart';
import '../../core/cipher.dart';
import '../../utils/typed_data.dart';
import '../padding.dart';

// TODO: can we use bits instead of blocks of bytes for (sbyte)?

/// Provides encryption for AES cipher in OFB mode.
class AESInOFBModeCipher extends Cipher with SaltedCipher {
  @override
  String get name =>
      "AES#${forEncryption ? 'encrypt' : 'decrypt'}/OFB/${Padding.none.name}";

  /// Whether the cipher is for encryption or decryption
  final bool forEncryption;

  /// Key for the cipher
  final Uint8List key; // 16, 24, or 32-bytes

  @override
  final Uint8List iv; // 16 or 32-bytes

  /// Number of bytes to use per block
  final int sbyte; // 1..16

  const AESInOFBModeCipher(
    this.forEncryption,
    this.key,
    this.iv,
    this.sbyte,
  );

  @override
  Uint8List convert(List<int> message) {
    int i, j, pos;
    int n = message.length;

    final output = Uint8List(n);
    final salt32 = Uint32List(4);
    final block32 = Uint32List(4); // 128-bit
    final iv32 = Uint32List.view(iv.buffer);
    final key32 = Uint32List.view(key.buffer);
    final salt = Uint8List.view(salt32.buffer);
    final block = Uint8List.view(block32.buffer);
    final xkey32 = AESCore.$expandEncryptionKey(key32);

    salt32[0] = iv32[0];
    salt32[1] = iv32[1];
    salt32[2] = iv32[2];
    salt32[3] = iv32[3];

    pos = sbyte;
    for (i = 0; i < n; ++i, ++pos) {
      if (pos == sbyte) {
        block32[0] = salt32[0];
        block32[1] = salt32[1];
        block32[2] = salt32[2];
        block32[3] = salt32[3];
        AESCore.$encryptLE(block32, xkey32);
        for (j = sbyte; j < 16; ++j) {
          salt[j - sbyte] = salt[j];
        }
        for (j = 0; j < sbyte; ++j) {
          salt[j + 16 - sbyte] = block[j];
        }
        j = 16 - sbyte;
        pos = 0;
      }
      output[i] = block[pos] ^ message[i];
    }

    return output;
  }
}

/// Provides encryption and decryption for AES cipher in OFB mode.
class AESInOFBMode extends CipherPair with SaltedCipher {
  @override
  String get name => "AES/OFB/${Padding.none.name}";

  @override
  final AESInOFBModeCipher encryptor;

  @override
  final AESInOFBModeCipher decryptor;

  const AESInOFBMode._({
    required this.encryptor,
    required this.decryptor,
  });

  @override
  Uint8List get iv => encryptor.iv;

  /// Creates AES cipher in OFB mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit random initialization vector or salt
  factory AESInOFBMode(
    List<int> key, {
    List<int>? iv,
    int sbyte = 8,
  }) {
    iv ??= randomBytes(16);
    if (iv.length != 16) {
      throw StateError('IV must be exactly 16-bytes');
    }
    final iv8 = toUint8List(iv);
    final key8 = toUint8List(key);
    return AESInOFBMode._(
      encryptor: AESInOFBModeCipher(true, key8, iv8, sbyte),
      decryptor: AESInOFBModeCipher(false, key8, iv8, sbyte),
    );
  }
}
