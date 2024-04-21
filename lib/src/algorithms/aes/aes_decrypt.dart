// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aes/aes_cache.dart';
import 'package:cipherlib/src/algorithms/aes/aes_encrypt.dart';
import 'package:cipherlib/src/core/stream_cipher.dart';

/// This implementation is based on **[NIST FIPS 197-upd1][nist]**.
///
/// [nist]: https://doi.org/10.6028/NIST.FIPS.197-upd1
class AESDecrypt implements BlockCipher {
  @override
  final String name = "AES-Decrypt";

  /// Key for the cipher
  final List<int> key;

  const AESDecrypt(this.key);

  @override
  Uint8List convert(List<int> input) {
    int n = input.length;
    if (n & 15 != 0) {
      throw StateError('Invalid input size');
    }

    var key8 = Uint8List.fromList(key);
    var dw = $expandKey(key8.buffer.asUint32List());

    var output = Uint8List(n);
    var block = Uint8List(16); // 128-bit
    var block32 = block.buffer.asUint32List();

    int i = 0, p = 0;
    for (int x in input) {
      block[i++] = x;
      if (i == 16) {
        i = 0;
        $decrypt(block32, dw);
        for (int b in block) {
          output[p++] = b;
        }
      }
    }
    return output;
  }

  @override
  Stream<int> stream(Stream<int> stream) async* {
    var key8 = Uint8List.fromList(key);
    var dw = $expandKey(key8.buffer.asUint32List());

    var block = Uint8List(16); // 128-bit
    var block32 = block.buffer.asUint32List();

    int i = 0;
    await for (int x in stream) {
      block[i++] = x;
      if (i == 16) {
        $decrypt(block32, dw);
        for (i = 0; i < 16; ++i) {
          yield block[i];
        }
        i = 0;
      }
    }
    if (i > 0) {
      throw StateError('Invalid input size');
    }
  }

  int get numberOfRounds {
    switch (key.length) {
      case 16: // 128-bit
        return 10;
      case 24: // 192-bit
        return 12;
      case 32: // 256-bit
        return 14;
      default:
        throw UnsupportedError('Invalid key length');
    }
  }

  /// Expands the key for AES decryption.
  static Uint32List $expandKey(Uint32List key) {
    var dw = AESEncrypt.$expandKey(key);
    for (int i = 4; i + 4 < dw.length; i++) {
      dw[i] = _wordMixInv(dw[i]);
    }
    return dw;
  }

  /// Decrypts a plaintext block.
  ///
  /// Parameters:
  /// - [box] : ciphertext as 32-bit words
  /// - [rk] : expanded key for decryption as 32-bit words
  static void $decrypt(Uint32List box, Uint32List rk) {
    int s0, s1, s2, s3, t0, t1, t2, t3;
    int n = rk.length - 1;
    // s = AddRoundKey(box)
    s3 = box[3] ^ rk[n--];
    s2 = box[2] ^ rk[n--];
    s1 = box[1] ^ rk[n--];
    s0 = box[0] ^ rk[n--];
    // Rounds: s = InvMixColumns(AddRoundKey(InvSubBytes(InvShiftRows(s))))
    while (n > 4) {
      t3 = _byteMix(s3, s2, s1, s0);
      t2 = _byteMix(s2, s1, s0, s3);
      t1 = _byteMix(s1, s0, s3, s2);
      t0 = _byteMix(s0, s3, s2, s1);
      s3 = t3 ^ rk[n--];
      s2 = t2 ^ rk[n--];
      s1 = t1 ^ rk[n--];
      s0 = t0 ^ rk[n--];
    }
    // box = AddRoundKey(InvSubBytes(InvShiftRows(s)))
    box[3] = _byteSub(s3, s2, s1, s0) ^ rk[n--];
    box[2] = _byteSub(s2, s1, s0, s3) ^ rk[n--];
    box[1] = _byteSub(s1, s0, s3, s2) ^ rk[n--];
    box[0] = _byteSub(s0, s3, s2, s1) ^ rk[n--];
  }

  @pragma('vm:prefer-inline')
  static int _byteSub(int s0, int s1, int s2, int s3) =>
      (AESCache.dsbox[(s0 >>> 24)] << 24) ^
      (AESCache.dsbox[(s1 >>> 16) & 0xFF] << 16) ^
      (AESCache.dsbox[(s2 >>> 8) & 0xFF] << 8) ^
      (AESCache.dsbox[(s3) & 0xFF]);

  @pragma('vm:prefer-inline')
  static int _byteMix(int s0, int s1, int s2, int s3) =>
      AESCache.dmix0[(s0 >>> 24)] ^
      AESCache.dmix1[(s1 >>> 16) & 0xFF] ^
      AESCache.dmix2[(s2 >>> 8) & 0xFF] ^
      AESCache.dmix3[(s3) & 0xFF];

  @pragma('vm:prefer-inline')
  static int _wordMixInv(int x) =>
      AESCache.dmix0[AESCache.sbox[(x >>> 24)]] ^
      AESCache.dmix1[AESCache.sbox[(x >>> 16) & 0xFF]] ^
      AESCache.dmix2[AESCache.sbox[(x >>> 8) & 0xFF]] ^
      AESCache.dmix3[AESCache.sbox[(x) & 0xFF]];
}
