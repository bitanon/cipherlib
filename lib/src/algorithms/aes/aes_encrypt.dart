// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aes/aes_cache.dart';
import 'package:cipherlib/src/core/stream_cipher.dart';

/// This implementation is based on **[NIST FIPS 197-upd1][nist]**.
///
/// [nist]: https://doi.org/10.6028/NIST.FIPS.197-upd1
class AESEncrypt implements BlockCipher {
  @override
  final String name = "AES-Encrypt";

  /// Key for the cipher
  final List<int> key;

  const AESEncrypt(this.key);

  @override
  Uint8List convert(List<int> input) {
    int n = input.length;
    if (n & 15 != 0) {
      throw StateError('Invalid input size');
    }

    var key8 = Uint8List.fromList(key);
    var w = $expandKey(key8.buffer.asUint32List());

    var output = Uint8List(n);
    var block = Uint8List(16); // 128-bit
    var block32 = block.buffer.asUint32List();

    int i = 0, p = 0;
    for (int x in input) {
      block[i++] = x;
      if (i == 16) {
        i = 0;
        $encrypt(block32, w);
        output.setAll(p, block);
        p += 16;
      }
    }
    return output;
  }

  @override
  Stream<int> stream(Stream<int> stream) async* {
    var key8 = Uint8List.fromList(key);
    var w = $expandKey(key8.buffer.asUint32List());

    var block = Uint8List(16); // 128-bit
    var block32 = block.buffer.asUint32List();

    int i = 0;
    await for (int x in stream) {
      block[i++] = x;
      if (i == 16) {
        $encrypt(block32, w);
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

  /// Expands the key for AES encryption.
  static Uint32List $expandKey(Uint32List key) {
    switch (key.lengthInBytes) {
      case 16: // 128-bit
        {
          int s0, s1, s2, s3;
          var w = Uint32List(44);
          s0 = w[00] = key[0];
          s1 = w[01] = key[1];
          s2 = w[02] = key[2];
          s3 = w[03] = key[3];
          // 0: 4..7
          s0 = w[04] = s0 ^ _wordSubRot(s3) ^ AESCache.rcon[0];
          s1 = w[05] = s1 ^ s0;
          s2 = w[06] = s2 ^ s1;
          s3 = w[07] = s3 ^ s2;
          // 1: 8..11
          s0 = w[08] = s0 ^ _wordSubRot(s3) ^ AESCache.rcon[1];
          s1 = w[09] = s1 ^ s0;
          s2 = w[10] = s2 ^ s1;
          s3 = w[11] = s3 ^ s2;
          // 2: 12..15
          s0 = w[12] = s0 ^ _wordSubRot(s3) ^ AESCache.rcon[2];
          s1 = w[13] = s1 ^ s0;
          s2 = w[14] = s2 ^ s1;
          s3 = w[15] = s3 ^ s2;
          // 3: 16..19
          s0 = w[16] = s0 ^ _wordSubRot(s3) ^ AESCache.rcon[3];
          s1 = w[17] = s1 ^ s0;
          s2 = w[18] = s2 ^ s1;
          s3 = w[19] = s3 ^ s2;
          // 4: 20..23
          s0 = w[20] = s0 ^ _wordSubRot(s3) ^ AESCache.rcon[4];
          s1 = w[21] = s1 ^ s0;
          s2 = w[22] = s2 ^ s1;
          s3 = w[23] = s3 ^ s2;
          // 5: 24..27
          s0 = w[24] = s0 ^ _wordSubRot(s3) ^ AESCache.rcon[5];
          s1 = w[25] = s1 ^ s0;
          s2 = w[26] = s2 ^ s1;
          s3 = w[27] = s3 ^ s2;
          // 6: 28..31
          s0 = w[28] = s0 ^ _wordSubRot(s3) ^ AESCache.rcon[6];
          s1 = w[29] = s1 ^ s0;
          s2 = w[30] = s2 ^ s1;
          s3 = w[31] = s3 ^ s2;
          // 7: 32..35
          s0 = w[32] = s0 ^ _wordSubRot(s3) ^ AESCache.rcon[7];
          s1 = w[33] = s1 ^ s0;
          s2 = w[34] = s2 ^ s1;
          s3 = w[35] = s3 ^ s2;
          // 8: 36..39
          s0 = w[36] = s0 ^ _wordSubRot(s3) ^ AESCache.rcon[8];
          s1 = w[37] = s1 ^ s0;
          s2 = w[38] = s2 ^ s1;
          s3 = w[39] = s3 ^ s2;
          // 9: 40..43
          s0 = w[40] = s0 ^ _wordSubRot(s3) ^ AESCache.rcon[9];
          s1 = w[41] = s1 ^ s0;
          s2 = w[42] = s2 ^ s1;
          s3 = w[43] = s3 ^ s2;
          // result
          return w;
        }
      case 24: // 192-bit
        {
          int s0, s1, s2, s3, s4, s5;
          var w = Uint32List(52);
          s0 = w[00] = key[0];
          s1 = w[01] = key[1];
          s2 = w[02] = key[2];
          s3 = w[03] = key[3];
          s4 = w[04] = key[4];
          s5 = w[05] = key[5];
          // 0: 6..11
          s0 = w[06] = s0 ^ _wordSubRot(s5) ^ AESCache.rcon[0];
          s1 = w[07] = s1 ^ s0;
          s2 = w[08] = s2 ^ s1;
          s3 = w[09] = s3 ^ s2;
          s4 = w[10] = s4 ^ s3;
          s5 = w[11] = s5 ^ s4;
          // 1: 12..17
          s0 = w[12] = s0 ^ _wordSubRot(s5) ^ AESCache.rcon[1];
          s1 = w[13] = s1 ^ s0;
          s2 = w[14] = s2 ^ s1;
          s3 = w[15] = s3 ^ s2;
          s4 = w[16] = s4 ^ s3;
          s5 = w[17] = s5 ^ s4;
          // 2: 18..23
          s0 = w[18] = s0 ^ _wordSubRot(s5) ^ AESCache.rcon[2];
          s1 = w[19] = s1 ^ s0;
          s2 = w[20] = s2 ^ s1;
          s3 = w[21] = s3 ^ s2;
          s4 = w[22] = s4 ^ s3;
          s5 = w[23] = s5 ^ s4;
          // 3: 24..29
          s0 = w[24] = s0 ^ _wordSubRot(s5) ^ AESCache.rcon[3];
          s1 = w[25] = s1 ^ s0;
          s2 = w[26] = s2 ^ s1;
          s3 = w[27] = s3 ^ s2;
          s4 = w[28] = s4 ^ s3;
          s5 = w[29] = s5 ^ s4;
          // 4: 30..35
          s0 = w[30] = s0 ^ _wordSubRot(s5) ^ AESCache.rcon[4];
          s1 = w[31] = s1 ^ s0;
          s2 = w[32] = s2 ^ s1;
          s3 = w[33] = s3 ^ s2;
          s4 = w[34] = s4 ^ s3;
          s5 = w[35] = s5 ^ s4;
          // 5: 36..41
          s0 = w[36] = s0 ^ _wordSubRot(s5) ^ AESCache.rcon[5];
          s1 = w[37] = s1 ^ s0;
          s2 = w[38] = s2 ^ s1;
          s3 = w[39] = s3 ^ s2;
          s4 = w[40] = s4 ^ s3;
          s5 = w[41] = s5 ^ s4;
          // 6: 42..47
          s0 = w[42] = s0 ^ _wordSubRot(s5) ^ AESCache.rcon[6];
          s1 = w[43] = s1 ^ s0;
          s2 = w[44] = s2 ^ s1;
          s3 = w[45] = s3 ^ s2;
          s4 = w[46] = s4 ^ s3;
          s5 = w[47] = s5 ^ s4;
          // 7: 48..51
          s0 = w[48] = s0 ^ _wordSubRot(s5) ^ AESCache.rcon[7];
          s1 = w[49] = s1 ^ s0;
          s2 = w[50] = s2 ^ s1;
          s3 = w[51] = s3 ^ s2;
          // result
          return w;
        }
      case 32: // 256-bit
        {
          int s0, s1, s2, s3, s4, s5, s6, s7;
          var w = Uint32List(60);
          s0 = w[00] = key[0];
          s1 = w[01] = key[1];
          s2 = w[02] = key[2];
          s3 = w[03] = key[3];
          s4 = w[04] = key[4];
          s5 = w[05] = key[5];
          s6 = w[06] = key[6];
          s7 = w[07] = key[7];
          // 0: 8..15
          s0 = w[08] = s0 ^ _wordSubRot(s7) ^ AESCache.rcon[0];
          s1 = w[09] = s1 ^ s0;
          s2 = w[10] = s2 ^ s1;
          s3 = w[11] = s3 ^ s2;
          s4 = w[12] = s4 ^ _wordSub(s3);
          s5 = w[13] = s5 ^ s4;
          s6 = w[14] = s6 ^ s5;
          s7 = w[15] = s7 ^ s6;
          // 1: 16..23
          s0 = w[16] = s0 ^ _wordSubRot(s7) ^ AESCache.rcon[1];
          s1 = w[17] = s1 ^ s0;
          s2 = w[18] = s2 ^ s1;
          s3 = w[19] = s3 ^ s2;
          s4 = w[20] = s4 ^ _wordSub(s3);
          s5 = w[21] = s5 ^ s4;
          s6 = w[22] = s6 ^ s5;
          s7 = w[23] = s7 ^ s6;
          // 2: 24..31
          s0 = w[24] = s0 ^ _wordSubRot(s7) ^ AESCache.rcon[2];
          s1 = w[25] = s1 ^ s0;
          s2 = w[26] = s2 ^ s1;
          s3 = w[27] = s3 ^ s2;
          s4 = w[28] = s4 ^ _wordSub(s3);
          s5 = w[29] = s5 ^ s4;
          s6 = w[30] = s6 ^ s5;
          s7 = w[31] = s7 ^ s6;
          // 3: 32..39
          s0 = w[32] = s0 ^ _wordSubRot(s7) ^ AESCache.rcon[3];
          s1 = w[33] = s1 ^ s0;
          s2 = w[34] = s2 ^ s1;
          s3 = w[35] = s3 ^ s2;
          s4 = w[36] = s4 ^ _wordSub(s3);
          s5 = w[37] = s5 ^ s4;
          s6 = w[38] = s6 ^ s5;
          s7 = w[39] = s7 ^ s6;
          // 4: 40..47
          s0 = w[40] = s0 ^ _wordSubRot(s7) ^ AESCache.rcon[4];
          s1 = w[41] = s1 ^ s0;
          s2 = w[42] = s2 ^ s1;
          s3 = w[43] = s3 ^ s2;
          s4 = w[44] = s4 ^ _wordSub(s3);
          s5 = w[45] = s5 ^ s4;
          s6 = w[46] = s6 ^ s5;
          s7 = w[47] = s7 ^ s6;
          // 5: 48..55
          s0 = w[48] = s0 ^ _wordSubRot(s7) ^ AESCache.rcon[5];
          s1 = w[49] = s1 ^ s0;
          s2 = w[50] = s2 ^ s1;
          s3 = w[51] = s3 ^ s2;
          s4 = w[52] = s4 ^ _wordSub(s3);
          s5 = w[53] = s5 ^ s4;
          s6 = w[54] = s6 ^ s5;
          s7 = w[55] = s7 ^ s6;
          // 6: 56..58
          s0 = w[56] = s0 ^ _wordSubRot(s7) ^ AESCache.rcon[6];
          s1 = w[57] = s1 ^ s0;
          s2 = w[58] = s2 ^ s1;
          s3 = w[59] = s3 ^ s2;
          // result
          return w;
        }
      default:
        throw UnsupportedError('Invalid key length');
    }
  }

  /// Encrypts a plaintext block.
  ///
  /// Parameters:
  /// - [box] : plaintext as 32-bit words
  /// - [rk] : expanded key for encryption as 32-bit words
  static void $encrypt(Uint32List box, Uint32List rk) {
    int s0, s1, s2, s3, t0, t1, t2, t3;
    int p = 0, n = rk.length - 4;
    // s = AddRoundKey(box)
    s0 = box[0] ^ rk[p++];
    s1 = box[1] ^ rk[p++];
    s2 = box[2] ^ rk[p++];
    s3 = box[3] ^ rk[p++];
    // Rounds: s = AddRoundKey(MixColumns(ShiftRows(SubTypes(s))))
    while (p < n) {
      t0 = _byteMix(s0, s1, s2, s3);
      t1 = _byteMix(s1, s2, s3, s0);
      t2 = _byteMix(s2, s3, s0, s1);
      t3 = _byteMix(s3, s0, s1, s2);
      s0 = t0 ^ rk[p++];
      s1 = t1 ^ rk[p++];
      s2 = t2 ^ rk[p++];
      s3 = t3 ^ rk[p++];
    }
    // box = AddRoundKey(ShiftRows(SubBytes(s)))
    box[0] = _byteSub(s0, s1, s2, s3) ^ rk[p++];
    box[1] = _byteSub(s1, s2, s3, s0) ^ rk[p++];
    box[2] = _byteSub(s2, s3, s0, s1) ^ rk[p++];
    box[3] = _byteSub(s3, s0, s1, s2) ^ rk[p++];
  }

  @pragma('vm:prefer-inline')
  static int _wordSub(int x) =>
      (AESCache.sbox[(x >>> 24)] << 24) ^
      (AESCache.sbox[(x >>> 16) & 0xFF] << 16) ^
      (AESCache.sbox[(x >>> 8) & 0xFF] << 8) ^
      (AESCache.sbox[(x) & 0xFF]);

  @pragma('vm:prefer-inline')
  static int _wordSubRot(int x) =>
      (AESCache.sbox[(x >>> 16) & 0xFF] << 24) ^
      (AESCache.sbox[(x >>> 8) & 0xFF] << 16) ^
      (AESCache.sbox[(x) & 0xFF] << 8) ^
      (AESCache.sbox[(x >>> 24)]);

  @pragma('vm:prefer-inline')
  static int _byteSub(int s0, int s1, int s2, int s3) =>
      (AESCache.sbox[(s0 >>> 24)] << 24) ^
      (AESCache.sbox[(s1 >>> 16) & 0xFF] << 16) ^
      (AESCache.sbox[(s2 >>> 8) & 0xFF] << 8) ^
      (AESCache.sbox[(s3) & 0xFF]);

  @pragma('vm:prefer-inline')
  static int _byteMix(int s0, int s1, int s2, int s3) =>
      AESCache.mix0[(s0 >>> 24)] ^
      AESCache.mix1[(s1 >>> 16) & 0xFF] ^
      AESCache.mix2[(s2 >>> 8) & 0xFF] ^
      AESCache.mix3[(s3) & 0xFF];
}
