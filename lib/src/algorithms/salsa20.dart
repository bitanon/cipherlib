// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/stream_cipher.dart';

const int _mask32 = 0xFFFFFFFF;

/// Salsa20 is a stream cipher designed to provide 256-bit
/// security. It uses a 256-bit key and a 64-bit nonce to generate a unique
/// keystream for each messages.
///
/// This implementation is based on the [Snuffle 2005 specification][spec]
///
/// [spec]: https://cr.yp.to/snuffle/spec.pdf
class Salsa20 implements StreamCipher {
  @override
  final String name = "Salsa20";

  /// Key for the cipher
  final List<int> key;

  const Salsa20(this.key);

  /// Salsa20 block generator
  Uint8List rounds(int size, [List<int>? nonce, int blockId = 0]) {
    if (size == 0) {
      return Uint8List(0);
    }
    var key8 = _validateKey(key);
    var key32 = key8.buffer.asUint32List();
    var nonce8 = _validateNonce(nonce);
    var nonce32 = nonce8.buffer.asUint32List();

    var state = Uint8List(size + (64 - (size & 63)));
    for (int pos = 64; pos <= state.length; pos += 64) {
      var state32 = state.buffer.asUint32List(pos - 64, 16);
      _block(state32, key32, nonce32, blockId++);
    }
    return state.buffer.asUint8List(0, size);
  }

  @override
  Uint8List convert(
    List<int> message, {
    List<int>? nonce,
    int blockId = 0,
  }) {
    var key8 = _validateKey(key);
    var key32 = key8.buffer.asUint32List();
    var nonce8 = _validateNonce(nonce);
    var nonce32 = nonce8.buffer.asUint32List();

    int pos = 0;
    var state = Uint32List(16);
    var state8 = state.buffer.asUint8List();
    var result = Uint8List.fromList(message);
    for (int i = 0; i < message.length; ++i) {
      if (pos == 0 || pos == 64) {
        _block(state, key32, nonce32, blockId++);
        pos = 0;
      }
      result[i] ^= state8[pos++];
    }
    return result;
  }

  @override
  Stream<int> stream(
    Stream<int> stream, {
    List<int>? nonce,
    int blockId = 0,
  }) async* {
    var key8 = _validateKey(key);
    var key32 = key8.buffer.asUint32List();
    var nonce8 = _validateNonce(nonce);
    var nonce32 = nonce8.buffer.asUint32List();

    int pos = 0;
    var state = Uint32List(16);
    var state8 = state.buffer.asUint8List();
    await for (var x in stream) {
      if (pos == 0 || pos == 64) {
        _block(state, key32, nonce32, blockId++);
        pos = 0;
      }
      yield (x ^ state8[pos++]) & 0xFF;
    }
  }

  @pragma('vm:prefer-inline')
  static Uint8List _validateKey(List<int> key) {
    if (key.length == 16 || key.length == 32) {
      return key is Uint8List ? key : Uint8List.fromList(key);
    }
    throw ArgumentError('The key should be either 16 or 32 bytes');
  }

  @pragma('vm:prefer-inline')
  static Uint8List _validateNonce(List<int>? nonce) {
    if (nonce == null) {
      return Uint8List(16);
    } else if (nonce.length == 8 || nonce.length == 16) {
      return nonce is Uint8List ? nonce : Uint8List.fromList(nonce);
    }
    throw ArgumentError('The nonce should be either 8 or 16 bytes');
  }

  @pragma('vm:prefer-inline')
  static int _rotl32(int x, int n) =>
      (((x << n) & _mask32) ^ ((x & _mask32) >>> (32 - n)));

  static void _block(Uint32List B, Uint32List K, Uint32List N, int blockId) {
    int i, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15;

    // init state
    if (K.lengthInBytes == 16) {
      s0 = B[0] = 0x61707865; // 'expa'
      s1 = B[1] = K[0];
      s2 = B[2] = K[1];
      s3 = B[3] = K[2];
      s4 = B[4] = K[3];
      s5 = B[5] = 0x3120646e; // 'nd 1'
      // 6..9 : nonce
      s10 = B[10] = 0x79622d36; // '6-by'
      s11 = B[11] = K[0];
      s12 = B[12] = K[1];
      s13 = B[13] = K[2];
      s14 = B[14] = K[3];
      s15 = B[15] = 0x6b206574; // 'te k'
    } else {
      s0 = B[0] = 0x61707865; // 'expa'
      s1 = B[1] = K[0];
      s2 = B[2] = K[1];
      s3 = B[3] = K[2];
      s4 = B[4] = K[3];
      s5 = B[5] = 0x3320646e; // 'nd 3'
      // 6..9 : nonce
      s10 = B[10] = 0x79622d32; // '2-by'
      s11 = B[11] = K[4];
      s12 = B[12] = K[5];
      s13 = B[13] = K[6];
      s14 = B[14] = K[7];
      s15 = B[15] = 0x6b206574; // 'te k'
    }
    // 6..9 : nonce
    if (N.lengthInBytes == 8) {
      s6 = B[6] = N[0];
      s7 = B[7] = N[1];
      s8 = B[8] = blockId;
      s9 = B[9] = blockId >>> 32;
    } else {
      s6 = B[6] = N[0];
      s7 = B[7] = N[1];
      s8 = B[8] = N[2];
      s9 = B[9] = N[3];
    }

    // 10 row(column) rounds
    for (i = 0; i < 10; i++) {
      // column rounds
      // qround(B, 0, 4, 8, 12);
      s4 ^= _rotl32(s0 + s12, 7);
      s8 ^= _rotl32(s4 + s0, 9);
      s12 ^= _rotl32(s8 + s4, 13);
      s0 ^= _rotl32(s12 + s8, 18);
      // qround(B, 5, 9, 13, 1);
      s9 ^= _rotl32(s5 + s1, 7);
      s13 ^= _rotl32(s9 + s5, 9);
      s1 ^= _rotl32(s13 + s9, 13);
      s5 ^= _rotl32(s1 + s13, 18);
      // qround(B, 10, 14, 2, 6)
      s14 ^= _rotl32(s10 + s6, 7);
      s2 ^= _rotl32(s14 + s10, 9);
      s6 ^= _rotl32(s2 + s14, 13);
      s10 ^= _rotl32(s6 + s2, 18);
      // qround(B, 15, 3, 7, 11)
      s3 ^= _rotl32(s15 + s11, 7);
      s7 ^= _rotl32(s3 + s15, 9);
      s11 ^= _rotl32(s7 + s3, 13);
      s15 ^= _rotl32(s11 + s7, 18);

      // row rounds
      // qround(B, 0, 1, 2, 3)
      s1 ^= _rotl32(s0 + s3, 7);
      s2 ^= _rotl32(s1 + s0, 9);
      s3 ^= _rotl32(s2 + s1, 13);
      s0 ^= _rotl32(s3 + s2, 18);
      // qround(B, 5, 6, 7, 4)
      s6 ^= _rotl32(s5 + s4, 7);
      s7 ^= _rotl32(s6 + s5, 9);
      s4 ^= _rotl32(s7 + s6, 13);
      s5 ^= _rotl32(s4 + s7, 18);
      // qround(B, 10, 11, 8, 9)
      s11 ^= _rotl32(s10 + s9, 7);
      s8 ^= _rotl32(s11 + s10, 9);
      s9 ^= _rotl32(s8 + s11, 13);
      s10 ^= _rotl32(s9 + s8, 18);
      // qround(B, 15, 12, 13, 14)
      s12 ^= _rotl32(s15 + s14, 7);
      s13 ^= _rotl32(s12 + s15, 9);
      s14 ^= _rotl32(s13 + s12, 13);
      s15 ^= _rotl32(s14 + s13, 18);
    }

    B[0] += s0;
    B[1] += s1;
    B[2] += s2;
    B[3] += s3;
    B[4] += s4;
    B[5] += s5;
    B[6] += s6;
    B[7] += s7;
    B[8] += s8;
    B[9] += s9;
    B[10] += s10;
    B[11] += s11;
    B[12] += s12;
    B[13] += s13;
    B[14] += s14;
    B[15] += s15;
  }
}
