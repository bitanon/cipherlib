// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../../core/aes.dart';
import '../../core/cipher.dart';
import '../../utils/typed_data.dart';
import '../padding.dart';

/// Provides encryption for AES cipher in IGE mode.
class AESInIGEModeEncrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#encrypt/IGE/${padding.name}";

  /// Key for the cipher
  final Uint8List key; // 16, 24, or 32-bytes

  @override
  final Uint8List iv; // 16 or 32-bytes

  /// Padding scheme for the input message
  final Padding padding;

  const AESInIGEModeEncrypt(
    this.key,
    this.iv, [
    this.padding = Padding.pkcs7,
  ]);

  @override
  Uint8List convert(List<int> message) {
    int i, j, n, m, pos;
    n = message.length;
    m = n + 16 - (n & 15);

    final output = Uint8List(m);
    final salt32 = Uint32List(8);
    final block32 = Uint32List(4); // 128-bit
    final iv32 = Uint32List.view(iv.buffer);
    final key32 = Uint32List.view(key.buffer);
    final salt = Uint8List.view(salt32.buffer);
    final block = Uint8List.view(block32.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xkey32 = AESCore.$expandEncryptionKey(key32);

    block32[0] = iv32[0];
    block32[1] = iv32[1];
    block32[2] = iv32[2];
    block32[3] = iv32[3];
    if (iv.length == 32) {
      salt32[0] = iv32[4];
      salt32[1] = iv32[5];
      salt32[2] = iv32[6];
      salt32[3] = iv32[7];
    }

    // process 16-byte blocks
    for (i = 0; i + 16 <= n; i += 16) {
      salt32[4] = (message[i + 0] ^
          (message[i + 1] << 8) ^
          (message[i + 2] << 16) ^
          (message[i + 3] << 24));
      salt32[5] = ((message[i + 4]) ^
          (message[i + 5] << 8) ^
          (message[i + 6] << 16) ^
          message[i + 7] << 24);
      salt32[6] = (message[i + 8] ^
          (message[i + 9] << 8) ^
          (message[i + 10] << 16) ^
          (message[i + 11] << 24));
      salt32[7] = (message[i + 12] ^
          (message[i + 13] << 8) ^
          (message[i + 14] << 16) ^
          (message[i + 15] << 24));

      block32[0] ^= salt32[4];
      block32[1] ^= salt32[5];
      block32[2] ^= salt32[6];
      block32[3] ^= salt32[7];

      AESCore.$encryptLE(block32, xkey32);

      block32[0] ^= salt32[0];
      block32[1] ^= salt32[1];
      block32[2] ^= salt32[2];
      block32[3] ^= salt32[3];

      salt32[0] = salt32[4];
      salt32[1] = salt32[5];
      salt32[2] = salt32[6];
      salt32[3] = salt32[7];

      j = i >>> 2;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];
      output32[j + 2] = block32[2];
      output32[j + 3] = block32[3];
    }

    // process last block
    for (pos = 0; i + pos < n; ++pos) {
      salt[pos + 16] = message[i + pos];
      block[pos] ^= message[i + pos];
    }
    if (padding.pad(salt, pos + 16)) {
      for (; pos < 16; pos++) {
        block[pos] ^= salt[pos + 16];
      }
      AESCore.$encryptLE(block32, xkey32);

      j = i >>> 2;
      output32[j + 0] = block32[0] ^ salt32[0];
      output32[j + 1] = block32[1] ^ salt32[1];
      output32[j + 2] = block32[2] ^ salt32[2];
      output32[j + 3] = block32[3] ^ salt32[3];

      i += 16;
      pos = 0;
    }

    if (pos != 0) {
      throw StateError('Invalid input size');
    }

    if (i == m) {
      return output;
    } else {
      return output.sublist(0, i);
    }
  }
}

/// Provides decryption for AES cipher in IGE mode.
class AESInIGEModeDecrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#decrypt/IGE/${padding.name}";

  /// Key for the cipher
  final Uint8List key; // 16, 24, or 32-bytes

  @override
  final Uint8List iv; // 16 or 32-bytes

  /// Padding scheme for the output message
  final Padding padding;

  const AESInIGEModeDecrypt(
    this.key,
    this.iv, [
    this.padding = Padding.pkcs7,
  ]);

  @override
  Uint8List convert(List<int> message) {
    int i, j, n;
    n = message.length;

    final output = Uint8List(n);
    final salt32 = Uint32List(8);
    final block32 = Uint32List(4); // 128-bit
    final iv32 = Uint32List.view(iv.buffer);
    final key32 = Uint32List.view(key.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xkey32 = AESCore.$expandDecryptionKey(key32);

    if ((n & 15) != 0) {
      throw StateError('Invalid input size');
    }

    salt32[0] = iv32[0];
    salt32[1] = iv32[1];
    salt32[2] = iv32[2];
    salt32[3] = iv32[3];
    if (iv.length == 32) {
      block32[0] = iv32[4];
      block32[1] = iv32[5];
      block32[2] = iv32[6];
      block32[3] = iv32[7];
    }

    // process 16-byte blocks
    for (i = 0; i + 16 <= n; i += 16) {
      salt32[4] = (message[i + 0] ^
          (message[i + 1] << 8) ^
          (message[i + 2] << 16) ^
          (message[i + 3] << 24));
      salt32[5] = ((message[i + 4]) ^
          (message[i + 5] << 8) ^
          (message[i + 6] << 16) ^
          message[i + 7] << 24);
      salt32[6] = (message[i + 8] ^
          (message[i + 9] << 8) ^
          (message[i + 10] << 16) ^
          (message[i + 11] << 24));
      salt32[7] = (message[i + 12] ^
          (message[i + 13] << 8) ^
          (message[i + 14] << 16) ^
          (message[i + 15] << 24));

      block32[0] ^= salt32[4];
      block32[1] ^= salt32[5];
      block32[2] ^= salt32[6];
      block32[3] ^= salt32[7];

      AESCore.$decryptLE(block32, xkey32);

      block32[0] ^= salt32[0];
      block32[1] ^= salt32[1];
      block32[2] ^= salt32[2];
      block32[3] ^= salt32[3];

      salt32[0] = salt32[4];
      salt32[1] = salt32[5];
      salt32[2] = salt32[6];
      salt32[3] = salt32[7];

      j = i >>> 2;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];
      output32[j + 2] = block32[2];
      output32[j + 3] = block32[3];
    }

    return padding.unpad(output);
  }
}

/// Provides encryption and decryption for AES cipher in IGE mode.
class AESInIGEMode extends CollateCipher with SaltedCipher {
  @override
  String get name => "AES/IGE/${padding.name}";

  @override
  final AESInIGEModeEncrypt encryptor;

  @override
  final AESInIGEModeDecrypt decryptor;

  @override
  Uint8List get iv => encryptor.iv;

  const AESInIGEMode._({
    required this.encryptor,
    required this.decryptor,
  });

  /// Creates AES cipher in IGE mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit random initialization vector or salt
  /// - [padding] The padding scheme for the messages
  factory AESInIGEMode(
    List<int> key, {
    List<int>? iv,
    Padding padding = Padding.pkcs7,
  }) {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
      throw StateError('Key must be 16, 24, or 32 bytes');
    }
    iv ??= randomBytes(32);
    if (iv.length != 16 && iv.length != 32) {
      throw StateError('IV must be 16 or 32-bytes');
    }
    final iv8 = toUint8List(iv);
    final key8 = toUint8List(key);
    return AESInIGEMode._(
      encryptor: AESInIGEModeEncrypt(key8, iv8, padding),
      decryptor: AESInIGEModeDecrypt(key8, iv8, padding),
    );
  }

  /// Padding scheme for the messages
  Padding get padding => encryptor.padding;
}
