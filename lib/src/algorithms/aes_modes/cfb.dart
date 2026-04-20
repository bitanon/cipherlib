// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../../core/aes.dart';
import '../../core/cipher.dart';
import '../padding.dart';

// TODO: (sbyte) instead of blocks of bytes, can we use bits?

/// Provides encryption for AES cipher in CFB mode.
class AESInCFBModeEncrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#encrypt/CFB/${Padding.none.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Number of bytes to use per block (1..16)
  final int sbyte;

  @override
  final Uint8List iv;

  const AESInCFBModeEncrypt(
    this.key,
    this.iv,
    this.sbyte,
  );

  @override
  Uint8List convert(List<int> message) {
    int i, j, p, pos;
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

    p = 0;
    pos = sbyte;
    j = 16 - sbyte;
    for (i = 0; i < n; ++i, ++j, ++p, ++pos) {
      if (pos == sbyte) {
        block32[0] = salt32[0];
        block32[1] = salt32[1];
        block32[2] = salt32[2];
        block32[3] = salt32[3];
        AESCore.$encryptLE(block32, xkey32);
        for (j = sbyte; j < 16; ++j) {
          salt[j - sbyte] = salt[j];
        }
        j = 16 - sbyte;
        pos = 0;
      }
      salt[j] = output[p] = block[pos] ^ message[i];
    }

    return output;
  }
}

/// Provides decryption for AES cipher in CFB mode.
class AESInCFBModeDecrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#decrypt/CFB/${Padding.none.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Number of bytes to use per block (1..16)
  final int sbyte;

  @override
  final Uint8List iv;

  const AESInCFBModeDecrypt(
    this.key,
    this.iv,
    this.sbyte,
  );

  @override
  Uint8List convert(List<int> message) {
    int i, j, p, pos;
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

    p = 0;
    pos = sbyte;
    j = 16 - sbyte;
    for (i = 0; i < n; ++i, ++j, ++p, ++pos) {
      if (pos == sbyte) {
        block32[0] = salt32[0];
        block32[1] = salt32[1];
        block32[2] = salt32[2];
        block32[3] = salt32[3];
        AESCore.$encryptLE(block32, xkey32);
        for (j = sbyte; j < 16; ++j) {
          salt[j - sbyte] = salt[j];
        }
        j = 16 - sbyte;
        pos = 0;
      }
      output[p] = block[pos] ^ (salt[j] = message[i]);
    }

    return output;
  }
}

/// Provides encryption and decryption for AES cipher in CFB mode.
class AESInCFBMode extends CollateCipher with SaltedCipher {
  @override
  String get name => "AES/CFB/${Padding.none.name}";

  @override
  final AESInCFBModeEncrypt encryptor;

  @override
  final AESInCFBModeDecrypt decryptor;

  const AESInCFBMode._({
    required this.encryptor,
    required this.decryptor,
  });

  @override
  Uint8List get iv => encryptor.iv;

  /// Creates AES cipher in CFB mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit random initialization vector or salt
  /// - [sbyte] number of bytes between 1 and 16 to take per block
  ///   to encrypt/decrypt plaintext.
  factory AESInCFBMode(
    List<int> key, {
    List<int>? iv,
    int sbyte = 8,
  }) {
    if (sbyte < 1 || sbyte > 16) {
      throw StateError('sbyte must be between 1 and 16');
    }
    iv ??= randomBytes(16);
    if (iv.length < 16) {
      throw StateError('IV must be at least 16-bytes');
    }
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    return AESInCFBMode._(
      encryptor: AESInCFBModeEncrypt(key8, iv8, sbyte),
      decryptor: AESInCFBModeDecrypt(key8, iv8, sbyte),
    );
  }
}
