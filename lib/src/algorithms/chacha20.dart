// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';
import 'package:cipherlib/src/core/utils.dart';

const int _mask32 = 0xFFFFFFFF;

/// ChaCha20 is a symmetric encryption algorithm designed to provide 256-bit
/// security. It uses a 256-bit key and a 64-bit nonce to generate a unique
/// keystream for each messages.
///
/// This implementation is based on the [RFC-8439][rfc]
///
/// [rfc]: https://datatracker.ietf.org/doc/html/rfc8439
class ChaCha20 extends SymmetricCipher {
  @override
  final String name = "ChaCha20";

  ChaCha20(List<int> key) : super(key.toUint8List()) {
    if (key.length != 32) {
      throw ArgumentError('The key should be 32 bytes');
    }
  }

  @override
  Uint8List convert(
    List<int> message, {
    List<int>? nonce,
    int blockCount = 1,
  }) {
    if (nonce != null && nonce.length != 12) {
      throw ArgumentError('The nonce should be 12 bytes');
    }
    int pos = 0;
    var state = Uint32List(16);
    var state8 = state.buffer.asUint8List();
    var key32 = key.buffer.asUint32List();
    var nonce8 = nonce is Uint8List
        ? nonce
        : nonce == null
            ? Uint8List(12)
            : Uint8List.fromList(nonce);
    var nonce32 = nonce8.buffer.asUint32List();
    var result = Uint8List.fromList(message);
    for (int i = 0; i < message.length; ++i) {
      if (pos == 0 || pos == 64) {
        _block(state, key32, nonce32, blockCount++);
        pos = 0;
      }
      result[i] ^= state8[pos++];
    }
    return result;
  }

  @override
  Stream<int> pipe(
    Stream<int> stream, {
    List<int>? nonce,
    int blockCount = 1,
  }) async* {
    if (nonce != null && nonce.length != 12) {
      throw ArgumentError('The nonce should be 12 bytes');
    }
    int pos = 0;
    var state = Uint32List(16);
    var state8 = state.buffer.asUint8List();
    var key32 = key.buffer.asUint32List();
    var nonce8 = nonce is Uint8List
        ? nonce
        : nonce == null
            ? Uint8List(12)
            : Uint8List.fromList(nonce);
    var nonce32 = nonce8.buffer.asUint32List();
    await for (var x in stream) {
      if (pos == 0 || pos == 64) {
        _block(state, key32, nonce32, blockCount++);
        pos = 0;
      }
      yield x ^ state8[pos++];
    }
  }

  /// ChaCha20 block generator
  Iterable<int> generate([
    List<int>? nonce,
    int blockCount = 1,
  ]) sync* {
    if (nonce != null && nonce.length != 12) {
      throw ArgumentError('The nonce should be 12 bytes');
    }
    var state = Uint32List(16);
    var state8 = state.buffer.asUint8List();
    var key32 = key.buffer.asUint32List();
    var nonce8 = nonce is Uint8List
        ? nonce
        : nonce == null
            ? Uint8List(12)
            : Uint8List.fromList(nonce);
    var nonce32 = nonce8.buffer.asUint32List();
    while (true) {
      _block(state, key32, nonce32, blockCount++);
      yield* state8;
    }
  }

  @pragma('vm:prefer-inline')
  static int _rotl32(int x, int n) =>
      (((x << n) & _mask32) ^ ((x & _mask32) >>> (32 - n)));

  static void _block(
    Uint32List state,
    Uint32List key,
    Uint32List nonce,
    int counter,
  ) {
    int i, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15;
    s0 = state[0] = 0x61707865;
    s1 = state[1] = 0x3320646e;
    s2 = state[2] = 0x79622d32;
    s3 = state[3] = 0x6b206574;
    s4 = state[4] = key[0];
    s5 = state[5] = key[1];
    s6 = state[6] = key[2];
    s7 = state[7] = key[3];
    s8 = state[8] = key[4];
    s9 = state[9] = key[5];
    s10 = state[10] = key[6];
    s11 = state[11] = key[7];
    s12 = state[12] = counter;
    s13 = state[13] = nonce[0];
    s14 = state[14] = nonce[1];
    s15 = state[15] = nonce[2];
    for (i = 0; i < 10; ++i) {
      // _round(state, 0, 4, 8, 12);
      s0 += s4;
      s12 = _rotl32(s12 ^ s0, 16);
      s8 += s12;
      s4 = _rotl32(s4 ^ s8, 12);
      s0 += s4;
      s12 = _rotl32(s12 ^ s0, 8);
      s8 += s12;
      s4 = _rotl32(s4 ^ s8, 7);
      // _round(state, 1, 5, 9, 13);
      s1 += s5;
      s13 = _rotl32(s13 ^ s1, 16);
      s9 += s13;
      s5 = _rotl32(s5 ^ s9, 12);
      s1 += s5;
      s13 = _rotl32(s13 ^ s1, 8);
      s9 += s13;
      s5 = _rotl32(s5 ^ s9, 7);
      // _round(state, 2, 6, 10, 14);
      s2 += s6;
      s14 = _rotl32(s14 ^ s2, 16);
      s10 += s14;
      s6 = _rotl32(s6 ^ s10, 12);
      s2 += s6;
      s14 = _rotl32(s14 ^ s2, 8);
      s10 += s14;
      s6 = _rotl32(s6 ^ s10, 7);
      // _round(state, 3, 7, 11, 15);
      s3 += s7;
      s15 = _rotl32(s15 ^ s3, 16);
      s11 += s15;
      s7 = _rotl32(s7 ^ s11, 12);
      s3 += s7;
      s15 = _rotl32(s15 ^ s3, 8);
      s11 += s15;
      s7 = _rotl32(s7 ^ s11, 7);
      // _round(state, 0, 5, 10, 15);
      s0 += s5;
      s15 = _rotl32(s15 ^ s0, 16);
      s10 += s15;
      s5 = _rotl32(s5 ^ s10, 12);
      s0 += s5;
      s15 = _rotl32(s15 ^ s0, 8);
      s10 += s15;
      s5 = _rotl32(s5 ^ s10, 7);
      // _round(state, 1, 6, 11, 12);
      s1 += s6;
      s12 = _rotl32(s12 ^ s1, 16);
      s11 += s12;
      s6 = _rotl32(s6 ^ s11, 12);
      s1 += s6;
      s12 = _rotl32(s12 ^ s1, 8);
      s11 += s12;
      s6 = _rotl32(s6 ^ s11, 7);
      // _round(state, 2, 7, 8, 13);
      s2 += s7;
      s13 = _rotl32(s13 ^ s2, 16);
      s8 += s13;
      s7 = _rotl32(s7 ^ s8, 12);
      s2 += s7;
      s13 = _rotl32(s13 ^ s2, 8);
      s8 += s13;
      s7 = _rotl32(s7 ^ s8, 7);
      // _round(state, 3, 4, 9, 14);
      s3 += s4;
      s14 = _rotl32(s14 ^ s3, 16);
      s9 += s14;
      s4 = _rotl32(s4 ^ s9, 12);
      s3 += s4;
      s14 = _rotl32(s14 ^ s3, 8);
      s9 += s14;
      s4 = _rotl32(s4 ^ s9, 7);
    }
    state[0] += s0;
    state[1] += s1;
    state[2] += s2;
    state[3] += s3;
    state[4] += s4;
    state[5] += s5;
    state[6] += s6;
    state[7] += s7;
    state[8] += s8;
    state[9] += s9;
    state[10] += s10;
    state[11] += s11;
    state[12] += s12;
    state[13] += s13;
    state[14] += s14;
    state[15] += s15;
  }
}
