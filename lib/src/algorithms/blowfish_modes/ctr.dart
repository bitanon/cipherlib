// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async' show Stream;
import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../../core/blowfish.dart';
import '../../core/cipher.dart';
import '../padding.dart';

int _mask32 = 0xFFFFFFFF;

/// Provides Blowfish cipher in CTR mode.
class BlowfishInCTRModeCipher extends StreamCipher with SaltedCipher {
  @override
  String get name => "Blowfish#cipher/CTR/${Padding.none.name}";

  /// Key for the cipher
  final Uint8List key;

  @override
  final Uint8List iv;

  /// Number of bits to use for the counter
  final int counterBits;

  const BlowfishInCTRModeCipher(
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
    int s0, s1;
    int t0, t1;

    t0 = s0 = counter32[0];
    t1 = s1 = counter32[1];

    s1 = (s1 + 1) & _mask32;
    if (s1 == 0 && bits > 32) {
      s0 = (s0 + 1) & _mask32;
    }

    if (bits > 32) {
      s0 = _splitMerge32(t0, s0, bits - 32);
    } else {
      s1 = _splitMerge32(t1, s1, bits);
    }

    counter32[0] = s0;
    counter32[1] = s1;
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
    BlowfishCore.$encrypt(block32, key32);
    block32[0] = BlowfishCore.$swap32(block32[0]);
    block32[1] = BlowfishCore.$swap32(block32[1]);
  }

  @override
  Uint8List convert(List<int> message) {
    int i, j, n;
    int b0, b1;
    n = message.length;

    final output = Uint8List(n);
    final block32 = Uint32List(2); // 64-bit
    final counter32 = Uint32List(2);
    final block = Uint8List.view(block32.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xkey32 = BlowfishCore.$expandKey(key);

    // initialize salt (nonce + counter) in little-endian order
    counter32[0] = (iv[0] << 24) | (iv[1] << 16) | (iv[2] << 8) | iv[3];
    counter32[1] = (iv[4] << 24) | (iv[5] << 16) | (iv[6] << 8) | iv[7];

    // process every 8-byte block
    for (i = 0; i + 8 <= n; i += 8) {
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

      j = i >>> 2;
      output32[j + 0] = block32[0] ^ b0;
      output32[j + 1] = block32[1] ^ b1;
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
    int pos = 8;

    final block32 = Uint32List(2); // 64-bit
    final counter32 = Uint32List(2);
    final block = Uint8List.view(block32.buffer);
    final xkey32 = BlowfishCore.$expandKey(key);

    // initialize salt (nonce + counter) in little-endian order
    counter32[0] = (iv[0] << 24) | (iv[1] << 16) | (iv[2] << 8) | iv[3];
    counter32[1] = (iv[4] << 24) | (iv[5] << 16) | (iv[6] << 8) | iv[7];

    await for (final chunk in stream) {
      if (chunk.isEmpty) {
        continue;
      }
      final output = Uint8List(chunk.length);
      for (i = 0; i < chunk.length; ++i, ++pos) {
        if (pos == 8) {
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

/// Provides encryption and decryption for Blowfish cipher in CTR mode.
class BlowfishInCTRMode extends StreamCipherPair with SaltedCipher {
  @override
  String get name => "Blowfish/CTR/${Padding.none.name}";

  @override
  final BlowfishInCTRModeCipher encryptor;

  @override
  final BlowfishInCTRModeCipher decryptor;

  const BlowfishInCTRMode._({
    required this.encryptor,
    required this.decryptor,
  });

  @override
  Uint8List get iv => encryptor.iv;

  /// Creates Blowfish cipher in CTR mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 64-bit salt (combination of nonce and counter)
  /// - [counterBits] Number of bits to use for the counter (1-64)
  factory BlowfishInCTRMode(
    List<int> key, [
    List<int>? iv,
    int counterBits = 64,
  ]) {
    if (key.isEmpty || key.length > 56) {
      throw StateError('Key must be between 1 and 56 bytes');
    }
    iv ??= randomBytes(8);
    if (iv.length != 8) {
      throw StateError('IV must be exactly 8-bytes');
    }
    if (counterBits < 1 || counterBits > 64) {
      throw StateError('Counter bits must be between 1 and 64');
    }
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    var cipher = BlowfishInCTRModeCipher(key8, iv8, counterBits);
    return BlowfishInCTRMode._(
      encryptor: cipher,
      decryptor: cipher,
    );
  }
}
