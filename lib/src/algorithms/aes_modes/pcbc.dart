// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../../core/aes.dart';
import '../../core/cipher.dart';
import '../../utils/typed_data.dart';
import '../padding.dart';

/// Provides encryption for AES cipher in PCBC mode.
class AESInPCBCModeEncrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#encrypt/PCBC/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  @override
  final Uint8List iv;

  /// Padding scheme for the input message
  final Padding padding;

  const AESInPCBCModeEncrypt(
    this.key,
    this.iv, [
    this.padding = Padding.pkcs7,
  ]);

  @override
  Uint8List convert(List<int> message) {
    int i, j, n, m, pos;
    int h0, h1, h2, h3;
    int s0, s1, s2, s3;
    n = message.length;
    m = n + 16 - (n & 15);

    final output = Uint8List(m);
    final block32 = Uint32List(4); // 128-bit
    final iv32 = Uint32List.view(iv.buffer);
    final key32 = Uint32List.view(key.buffer);
    final block = Uint8List.view(block32.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xkey32 = AESCore.$expandEncryptionKey(key32);

    s0 = iv32[0];
    s1 = iv32[1];
    s2 = iv32[2];
    s3 = iv32[3];

    // process 16-byte blocks
    for (i = 0; i + 16 <= n; i += 16) {
      h0 = (message[i + 0] ^
          (message[i + 1] << 8) ^
          (message[i + 2] << 16) ^
          (message[i + 3] << 24));
      h1 = ((message[i + 4]) ^
          (message[i + 5] << 8) ^
          (message[i + 6] << 16) ^
          message[i + 7] << 24);
      h2 = (message[i + 8] ^
          (message[i + 9] << 8) ^
          (message[i + 10] << 16) ^
          (message[i + 11] << 24));
      h3 = (message[i + 12] ^
          (message[i + 13] << 8) ^
          (message[i + 14] << 16) ^
          (message[i + 15] << 24));

      block32[0] = h0 ^ s0;
      block32[1] = h1 ^ s1;
      block32[2] = h2 ^ s2;
      block32[3] = h3 ^ s3;

      AESCore.$encryptLE(block32, xkey32);

      s0 = block32[0] ^ h0;
      s1 = block32[1] ^ h1;
      s2 = block32[2] ^ h2;
      s3 = block32[3] ^ h3;

      j = i >>> 2;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];
      output32[j + 2] = block32[2];
      output32[j + 3] = block32[3];
    }

    // process last block
    for (pos = 0; i + pos < n; ++pos) {
      block[pos] = message[i + pos];
    }
    if (padding.pad(block, pos)) {
      block32[0] ^= s0;
      block32[1] ^= s1;
      block32[2] ^= s2;
      block32[3] ^= s3;

      AESCore.$encryptLE(block32, xkey32);

      j = i >>> 2;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];
      output32[j + 2] = block32[2];
      output32[j + 3] = block32[3];

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

/// Provides decryption for AES cipher in PCBC mode.
class AESInPCBCModeDecrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#decrypt/PCBC/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  @override
  final Uint8List iv;

  /// Padding scheme for the output message
  final Padding padding;

  const AESInPCBCModeDecrypt(
    this.key,
    this.iv, [
    this.padding = Padding.pkcs7,
  ]);

  @override
  Uint8List convert(List<int> message) {
    int i, j;
    int s0, s1, s2, s3;
    int t0, t1, t2, t3;
    int n = message.length;

    final output = Uint8List(n);
    final block32 = Uint32List(4); // 128-bit
    final iv32 = Uint32List.view(iv.buffer);
    final key32 = Uint32List.view(key.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xkey32 = AESCore.$expandDecryptionKey(key32);

    if (n & 15 != 0) {
      throw StateError('Invalid input size');
    }

    s0 = iv32[0];
    s1 = iv32[1];
    s2 = iv32[2];
    s3 = iv32[3];

    // process 16-byte blocks
    for (i = 0; i + 16 <= n; i += 16) {
      t0 = (message[i + 0] ^
          (message[i + 1] << 8) ^
          (message[i + 2] << 16) ^
          (message[i + 3] << 24));
      t1 = ((message[i + 4]) ^
          (message[i + 5] << 8) ^
          (message[i + 6] << 16) ^
          message[i + 7] << 24);
      t2 = (message[i + 8] ^
          (message[i + 9] << 8) ^
          (message[i + 10] << 16) ^
          (message[i + 11] << 24));
      t3 = (message[i + 12] ^
          (message[i + 13] << 8) ^
          (message[i + 14] << 16) ^
          (message[i + 15] << 24));

      block32[0] = t0;
      block32[1] = t1;
      block32[2] = t2;
      block32[3] = t3;

      AESCore.$decryptLE(block32, xkey32);

      s0 ^= block32[0];
      s1 ^= block32[1];
      s2 ^= block32[2];
      s3 ^= block32[3];

      j = i >>> 2;
      output32[j + 0] = s0;
      output32[j + 1] = s1;
      output32[j + 2] = s2;
      output32[j + 3] = s3;

      s0 ^= t0;
      s1 ^= t1;
      s2 ^= t2;
      s3 ^= t3;
    }

    return padding.unpad(output);
  }
}

/// Provides encryption and decryption for AES cipher in PCBC mode.
class AESInPCBCMode extends CollateCipher with SaltedCipher {
  @override
  String get name => "AES/PCBC/${padding.name}";

  @override
  final AESInPCBCModeEncrypt encryptor;

  @override
  final AESInPCBCModeDecrypt decryptor;

  const AESInPCBCMode._({
    required this.encryptor,
    required this.decryptor,
  });

  @override
  Uint8List get iv => encryptor.iv;

  /// Creates AES cipher in PCBC mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit random initialization vector or salt
  /// - [padding] The padding scheme for the messages
  factory AESInPCBCMode(
    List<int> key, {
    List<int>? iv,
    Padding padding = Padding.pkcs7,
  }) {
    iv ??= randomBytes(16);
    if (iv.length != 16) {
      throw StateError('IV must be exactly 16-bytes');
    }
    final iv8 = toUint8List(iv);
    final key8 = toUint8List(key);
    return AESInPCBCMode._(
      encryptor: AESInPCBCModeEncrypt(key8, iv8, padding),
      decryptor: AESInPCBCModeDecrypt(key8, iv8, padding),
    );
  }

  /// Padding scheme for the messages
  Padding get padding => encryptor.padding;
}
