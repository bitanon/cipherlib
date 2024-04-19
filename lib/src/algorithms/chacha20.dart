// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/stream_cipher.dart';

const int _mask32 = 0xFFFFFFFF;

/// ChaCha20 is a stream cipher designed to provide 256-bit security.
/// It uses a 256-bit key and a 64-bit nonce to generate a unique
/// keystream for each messages.
///
/// This implementation is based on the [RFC-8439][rfc]
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc8439.html
class ChaCha20 implements StreamCipher {
  @override
  final String name = "ChaCha20";

  /// Key for the cipher
  final List<int> key;

  const ChaCha20(this.key);

  /// ChaCha20 block generator
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
    int blockId = 1,
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
    int blockId = 1,
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
    if (key.length == 8 || key.length == 32) {
      return key is Uint8List ? key : Uint8List.fromList(key);
    }
    throw ArgumentError('The key should be either 8 or 32 bytes');
  }

  @pragma('vm:prefer-inline')
  static Uint8List _validateNonce(List<int>? nonce) {
    if (nonce == null) {
      return Uint8List(12);
    } else if (nonce.length == 8 || nonce.length == 12) {
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
      s1 = B[1] = 0x3120646e; // 'nd 1'
      s2 = B[2] = 0x79622d36; // '6-by'
      s3 = B[3] = 0x6b206574; // 'te k
      s4 = B[4] = K[0];
      s5 = B[5] = K[1];
      s6 = B[6] = K[2];
      s7 = B[7] = K[3];
      s8 = B[8] = K[4];
      s9 = B[9] = K[5];
      s10 = B[10] = K[6];
      s11 = B[11] = K[7];
    } else {
      s0 = B[0] = 0x61707865; // 'expa'
      s1 = B[1] = 0x3320646e; // 'nd 3'
      s2 = B[2] = 0x79622d32; // '2-by'
      s3 = B[3] = 0x6b206574; // 'te k
      s4 = B[4] = K[0];
      s5 = B[5] = K[1];
      s6 = B[6] = K[2];
      s7 = B[7] = K[3];
      s8 = B[8] = K[4];
      s9 = B[9] = K[5];
      s10 = B[10] = K[6];
      s11 = B[11] = K[7];
    }
    s12 = B[12] = blockId;
    if (N.lengthInBytes == 8) {
      s13 = B[13] = blockId >>> 32;
      s14 = B[14] = N[0];
      s15 = B[15] = N[1];
    } else {
      s13 = B[13] = N[0];
      s14 = B[14] = N[1];
      s15 = B[15] = N[2];
    }

    // 10 diagonal(column) rounds
    for (i = 0; i < 10; ++i) {
      // column rounds
      // qround(B, 0, 4, 8, 12);
      s0 += s4;
      s12 = _rotl32(s12 ^ s0, 16);
      s8 += s12;
      s4 = _rotl32(s4 ^ s8, 12);
      s0 += s4;
      s12 = _rotl32(s12 ^ s0, 8);
      s8 += s12;
      s4 = _rotl32(s4 ^ s8, 7);
      // qround(B, 1, 5, 9, 13);
      s1 += s5;
      s13 = _rotl32(s13 ^ s1, 16);
      s9 += s13;
      s5 = _rotl32(s5 ^ s9, 12);
      s1 += s5;
      s13 = _rotl32(s13 ^ s1, 8);
      s9 += s13;
      s5 = _rotl32(s5 ^ s9, 7);
      // qround(B, 2, 6, 10, 14);
      s2 += s6;
      s14 = _rotl32(s14 ^ s2, 16);
      s10 += s14;
      s6 = _rotl32(s6 ^ s10, 12);
      s2 += s6;
      s14 = _rotl32(s14 ^ s2, 8);
      s10 += s14;
      s6 = _rotl32(s6 ^ s10, 7);
      // qround(B, 3, 7, 11, 15);
      s3 += s7;
      s15 = _rotl32(s15 ^ s3, 16);
      s11 += s15;
      s7 = _rotl32(s7 ^ s11, 12);
      s3 += s7;
      s15 = _rotl32(s15 ^ s3, 8);
      s11 += s15;
      s7 = _rotl32(s7 ^ s11, 7);

      // diagonal rounds
      // qround(B, 0, 5, 10, 15);
      s0 += s5;
      s15 = _rotl32(s15 ^ s0, 16);
      s10 += s15;
      s5 = _rotl32(s5 ^ s10, 12);
      s0 += s5;
      s15 = _rotl32(s15 ^ s0, 8);
      s10 += s15;
      s5 = _rotl32(s5 ^ s10, 7);
      // qround(B, 1, 6, 11, 12);
      s1 += s6;
      s12 = _rotl32(s12 ^ s1, 16);
      s11 += s12;
      s6 = _rotl32(s6 ^ s11, 12);
      s1 += s6;
      s12 = _rotl32(s12 ^ s1, 8);
      s11 += s12;
      s6 = _rotl32(s6 ^ s11, 7);
      // qround(B, 2, 7, 8, 13);
      s2 += s7;
      s13 = _rotl32(s13 ^ s2, 16);
      s8 += s13;
      s7 = _rotl32(s7 ^ s8, 12);
      s2 += s7;
      s13 = _rotl32(s13 ^ s2, 8);
      s8 += s13;
      s7 = _rotl32(s7 ^ s8, 7);
      // qround(B, 3, 4, 9, 14);
      s3 += s4;
      s14 = _rotl32(s14 ^ s3, 16);
      s9 += s14;
      s4 = _rotl32(s4 ^ s9, 12);
      s3 += s4;
      s14 = _rotl32(s14 ^ s3, 8);
      s9 += s14;
      s4 = _rotl32(s4 ^ s9, 7);
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
