// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async' show Stream;
import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../../core/aes.dart';
import '../../core/cipher.dart';
import '../../utils/nonce.dart';
import '../padding.dart';

int _mask32 = 0xFFFFFFFF;

/// Provides AES cipher in CTR mode.
class AESInCTRModeCipher extends StreamCipher with SaltedCipher {
  @override
  String get name => "AES#cipher/CTR/${Padding.none.name}";

  /// Key for the cipher
  final Uint8List key;

  @override
  final Uint8List iv;

  /// Number of bytes to use for the counter
  final int counterBits;

  const AESInCTRModeCipher(
    this.key,
    this.iv, [
    this.counterBits = 64,
  ]);

  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  static int _splitMerge32(int a, int b, int s) {
    return ((a >>> s) << s) | (b & ((1 << s) - 1));
  }

  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  static void _increment(Uint32List counter32, int bits) {
    int s0, s1, s2, s3;
    int t0, t1, t2, t3;

    t0 = s0 = counter32[0];
    t1 = s1 = counter32[1];
    t2 = s2 = counter32[2];
    t3 = s3 = counter32[3];

    s3 = (s3 + 1) & _mask32;
    if (s3 == 0 && bits > 32) {
      s2 = (s2 + 1) & _mask32;
      if (s2 == 0 && bits > 64) {
        s1 = (s1 + 1) & _mask32;
        if (s1 == 0 && bits > 96) {
          s0 = (s0 + 1) & _mask32;
        }
      }
    }

    if (bits > 96) {
      s0 = _splitMerge32(t0, s0, bits - 96);
    } else if (bits > 64) {
      s1 = _splitMerge32(t1, s1, bits - 64);
    } else if (bits > 32) {
      s2 = _splitMerge32(t2, s2, bits - 32);
    } else {
      s3 = _splitMerge32(t3, s3, bits);
    }

    counter32[0] = s0;
    counter32[1] = s1;
    counter32[2] = s2;
    counter32[3] = s3;
  }

  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  static void _encryptBlock(
    Uint32List key32,
    Uint32List block32,
    Uint32List counter32,
  ) {
    block32[0] = counter32[0];
    block32[1] = counter32[1];
    block32[2] = counter32[2];
    block32[3] = counter32[3];
    AESCore.$encrypt(block32, key32);
    block32[0] = AESCore.$swap32(block32[0]);
    block32[1] = AESCore.$swap32(block32[1]);
    block32[2] = AESCore.$swap32(block32[2]);
    block32[3] = AESCore.$swap32(block32[3]);
  }

  @override
  Uint8List convert(List<int> message) {
    int i, j, n;
    int b0, b1, b2, b3;
    n = message.length;

    final output = Uint8List(n);
    final block32 = Uint32List(4); // 128-bit
    final counter32 = Uint32List(4);
    final key32 = Uint32List.view(key.buffer);
    final block = Uint8List.view(block32.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xkey32 = AESCore.$expandEncryptionKey(key32);

    // initialize salt (nonce + counter) in little-endian order
    counter32[0] = (iv[0] << 24) | (iv[1] << 16) | (iv[2] << 8) | iv[3];
    counter32[1] = (iv[4] << 24) | (iv[5] << 16) | (iv[6] << 8) | iv[7];
    counter32[2] = (iv[8] << 24) | (iv[9] << 16) | (iv[10] << 8) | iv[11];
    counter32[3] = (iv[12] << 24) | (iv[13] << 16) | (iv[14] << 8) | iv[15];

    // process every 16-byte block
    for (i = 0; i + 16 <= n; i += 16) {
      _encryptBlock(xkey32, block32, counter32);
      _increment(counter32, counterBits);

      b0 = (message[i + 0] |
          (message[i + 1] << 8) |
          (message[i + 2] << 16) |
          (message[i + 3] << 24));
      b1 = (message[i + 4] |
          (message[i + 5] << 8) |
          (message[i + 6] << 16) |
          (message[i + 7] << 24));
      b2 = (message[i + 8] |
          (message[i + 9] << 8) |
          (message[i + 10] << 16) |
          (message[i + 11] << 24));
      b3 = (message[i + 12] |
          (message[i + 13] << 8) |
          (message[i + 14] << 16) |
          (message[i + 15] << 24));

      j = i >>> 2;
      output32[j + 0] = block32[0] ^ b0;
      output32[j + 1] = block32[1] ^ b1;
      output32[j + 2] = block32[2] ^ b2;
      output32[j + 3] = block32[3] ^ b3;
    }

    // process remaining bytes
    if (i < n) {
      _encryptBlock(xkey32, block32, counter32);
      for (j = 0; i < n; ++i, ++j) {
        output[i] = block[j] ^ message[i];
      }
    }

    return output;
  }

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) async* {
    int i;
    int pos = 16;

    final block32 = Uint32List(4); // 128-bit
    final counter32 = Uint32List(4);
    final key32 = Uint32List.view(key.buffer);
    final block = Uint8List.view(block32.buffer);
    final xkey32 = AESCore.$expandEncryptionKey(key32);

    // initialize salt (nonce + counter) in little-endian order
    counter32[0] = (iv[0] << 24) | (iv[1] << 16) | (iv[2] << 8) | iv[3];
    counter32[1] = (iv[4] << 24) | (iv[5] << 16) | (iv[6] << 8) | iv[7];
    counter32[2] = (iv[8] << 24) | (iv[9] << 16) | (iv[10] << 8) | iv[11];
    counter32[3] = (iv[12] << 24) | (iv[13] << 16) | (iv[14] << 8) | iv[15];

    await for (final chunk in stream) {
      if (chunk.isEmpty) {
        continue;
      }
      final output = Uint8List(chunk.length);
      for (i = 0; i < chunk.length; ++i, ++pos) {
        if (pos == 16) {
          _encryptBlock(xkey32, block32, counter32);
          _increment(counter32, counterBits);
          pos = 0;
        }
        output[i] = block[pos] ^ chunk[i];
      }
      yield output;
    }
  }
}

/// Provides encryption and decryption for AES cipher in CTR mode.
class AESInCTRMode extends StreamCipherPair with SaltedCipher {
  @override
  String get name => "AES/CTR/${Padding.none.name}";

  @override
  final AESInCTRModeCipher encryptor;

  @override
  final AESInCTRModeCipher decryptor;

  const AESInCTRMode._({
    required this.encryptor,
    required this.decryptor,
  });

  @override
  Uint8List get iv => encryptor.iv;

  /// Creates AES cipher in CTR mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit salt (combination of nonce and counter)
  /// - [counterBits] Number of bits to use for the counter (1-128)
  factory AESInCTRMode(
    List<int> key, [
    List<int>? iv,
    int counterBits = 64,
  ]) {
    iv ??= randomBytes(16);
    if (iv.length != 16) {
      throw StateError('IV must be exactly 16-bytes');
    }
    if (counterBits < 1 || counterBits > 128) {
      throw StateError('Counter bits must be between 1 and 128');
    }
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    var cipher = AESInCTRModeCipher(key8, iv8, counterBits);
    return AESInCTRMode._(
      encryptor: cipher,
      decryptor: cipher,
    );
  }

  /// Creates AES cipher in CTR mode.
  /// If [nonce] and [counter] are not provided, random values are used.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [nonce] 64-bit nonce
  /// - [counter] 64-bit counter
  factory AESInCTRMode.iv(
    List<int> key, {
    Nonce64? nonce,
    Nonce64? counter,
  }) {
    final iv = Uint8List(16);
    nonce ??= Nonce64.random();
    counter ??= Nonce64.random();
    iv.setRange(0, 8, nonce.reverse().bytes);
    iv.setRange(8, 16, counter.reverse().bytes);
    return AESInCTRMode(key, iv, 64);
  }
}
