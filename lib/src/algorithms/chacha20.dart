// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:cipherlib/src/core/salted_cipher.dart';
import 'package:cipherlib/src/utils/nonce.dart';
import 'package:hashlib/hashlib.dart' show randomBytes;

const int _mask32 = 0xFFFFFFFF;

/// This sink is used by the [ChaCha20] algorithm.
class ChaCha20Sink extends CipherSink {
  ChaCha20Sink(this._key, this._nonce, this._counter) {
    if (_key.length != 16 && _key.length != 32) {
      throw ArgumentError('The key should be either 16 or 32 bytes');
    }
    if (_nonce.length != 8 && _nonce.length != 12) {
      throw ArgumentError('The nonce should be either 8 or 12 bytes');
    }
    if (_counter.length != 4 && _counter.length != 8) {
      throw ArgumentError('The counter should be either 4 or 8 bytes');
    }
    _counterSize = _nonce.length == 8 ? 8 : 4;
    reset();
  }

  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;
  final Uint8List _nonce;
  final Uint8List _counter;
  late final int _counterSize;
  final _iv = Uint8List(16);
  final _state = Uint32List(16);
  late final _state8 = _state.buffer.asUint8List();
  late final _key32 = _key.buffer.asUint32List();
  late final _iv32 = _iv.buffer.asUint32List();

  @override
  bool get closed => _closed;

  @override
  void reset() {
    _pos = 0;
    _closed = false;
    for (int i = 0; i < _counterSize; ++i) {
      _iv[i] = _counter[i];
    }
    for (int i = _counterSize; i < 16; ++i) {
      _iv[i] = _nonce[i - _counterSize];
    }
    _block(_state, _key32, _iv32);
    _increment();
  }

  @override
  Uint8List add(
    List<int> data, [
    int start = 0,
    int? end,
    bool last = false,
  ]) {
    if (_closed) {
      throw StateError('The sink is closed');
    }
    _closed = last;
    end ??= data.length;

    var result = Uint8List(end - start);
    for (int i = start; i < end; i++) {
      if (_pos == 64) {
        _block(_state, _key32, _iv32);
        _increment();
        _pos = 0;
      }
      result[i] = data[i] ^ _state8[_pos++];
    }
    return result;
  }

  void _increment() {
    for (int i = 0; i < _counterSize; ++i) {
      if ((++_iv[i]) != 0) return;
    }
  }

  @pragma('vm:prefer-inline')
  static int _rotl32(int x, int n) =>
      (((x << n) & _mask32) ^ ((x & _mask32) >>> (32 - n)));

  static void _block(Uint32List B, Uint32List K, Uint32List N) {
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
      s8 = B[8] = K[0];
      s9 = B[9] = K[1];
      s10 = B[10] = K[2];
      s11 = B[11] = K[3];
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
    s12 = B[12] = N[0];
    s13 = B[13] = N[1];
    s14 = B[14] = N[2];
    s15 = B[15] = N[3];

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

/// ChaCha20 is a stream cipher designed to provide 256-bit security.
/// It uses a 256-bit key and a 64-bit nonce to generate a unique
/// keystream for each messages.
///
/// This implementation is based on the [RFC-8439][rfc]
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc8439.html
class ChaCha20 extends SaltedCipher {
  @override
  final String name = "ChaCha20";

  /// Key for the cipher
  final Uint8List key;

  /// The initial block id
  final Uint8List counter;

  const ChaCha20(
    this.key,
    Uint8List nonce,
    this.counter,
  ) : super(nonce);

  /// Creates a [ChaCha20] with List<int> [key], and [nonce].
  ///
  /// Every elements of the both list is transformed to unsigned 8-bit numbers.
  factory ChaCha20.fromList(
    List<int> key, {
    List<int>? nonce,
    Nonce64? counter,
  }) {
    nonce ??= randomBytes(8);
    counter ??= Nonce64.int64(1);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    var nonce8 = nonce is Uint8List ? nonce : Uint8List.fromList(nonce);
    return ChaCha20(key8, nonce8, counter.bytes);
  }

  @override
  @pragma('vm:prefer-inline')
  CipherSink createSink() => ChaCha20Sink(key, iv, counter);
}
