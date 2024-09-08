// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:cipherlib/src/core/salted_cipher.dart';
import 'package:cipherlib/src/utils/nonce.dart';
import 'package:hashlib/hashlib.dart' show randomBytes;

const int _mask32 = 0xFFFFFFFF;

/// This sink is used by the [Salsa20] algorithm.
class Salsa20Sink extends CipherSink {
  Salsa20Sink(this._key, this._nonce, this._counter) {
    if (_key.length != 16 && _key.length != 32) {
      throw ArgumentError('The key should be either 16 or 32 bytes');
    }
    if (_nonce.length != 8 && _nonce.length != 16) {
      throw ArgumentError('The nonce should be either 8 or 16 bytes');
    }
    _needCounter = _nonce.length == 8;
    if (_needCounter && _counter.length < 8) {
      throw ArgumentError('The counter should be 8 bytes');
    }
    reset();
  }

  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;
  final Uint8List _nonce;
  final Uint8List _counter;
  final _iv = Uint8List(16);
  final _state = Uint32List(16);
  late final bool _needCounter;
  late final _state8 = _state.buffer.asUint8List();
  late final _key32 = _key.buffer.asUint32List();
  late final _iv32 = _iv.buffer.asUint32List();

  @override
  bool get closed => _closed;

  @override
  void reset() {
    _pos = 0;
    _closed = false;
    for (int i = 0; i < _nonce.length; ++i) {
      _iv[i] = _nonce[i];
    }
    if (_needCounter) {
      for (int i = 8; i < 16; ++i) {
        _iv[i] = _counter[i - 8];
      }
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
    if (_needCounter) {
      for (int i = 8; i < 16; ++i) {
        if ((++_iv[i]) != 0) return;
      }
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
      s1 = B[1] = K[0];
      s2 = B[2] = K[1];
      s3 = B[3] = K[2];
      s4 = B[4] = K[3];
      s5 = B[5] = 0x3120646e; // 'nd 1'
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
      s10 = B[10] = 0x79622d32; // '2-by'
      s11 = B[11] = K[4];
      s12 = B[12] = K[5];
      s13 = B[13] = K[6];
      s14 = B[14] = K[7];
      s15 = B[15] = 0x6b206574; // 'te k'
    }
    s6 = B[6] = N[0];
    s7 = B[7] = N[1];
    s8 = B[8] = N[2];
    s9 = B[9] = N[3];

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

/// Salsa20 is a stream cipher designed to provide 256-bit
/// security. It uses a 256-bit key and a 64-bit nonce to generate a unique
/// keystream for each messages.
///
/// This implementation is based on the [Snuffle 2005 specification][spec]
///
/// [spec]: https://cr.yp.to/snuffle/spec.pdf
class Salsa20 extends SaltedCipher {
  @override
  final String name = "Salsa20";

  /// Key for the cipher
  final Uint8List key;

  /// The initial block id
  final Uint8List counter;

  const Salsa20._(
    this.key,
    Uint8List nonce,
    this.counter,
  ) : super(nonce);

  /// Creates a [Salsa20] with List<int> [key], and [nonce].
  ///
  /// Every elements of the both list is transformed to unsigned 8-bit numbers.
  factory Salsa20(
    List<int> key, {
    List<int>? nonce,
    Nonce64? counter,
  }) {
    nonce ??= randomBytes(16);
    counter ??= Nonce64.zero();
    var counter8 = counter.bytes;
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    var nonce8 = nonce is Uint8List ? nonce : Uint8List.fromList(nonce);
    return Salsa20._(key8, nonce8, counter8);
  }

  @override
  @pragma('vm:prefer-inline')
  Salsa20Sink createSink() => Salsa20Sink(key, iv, counter);
}
