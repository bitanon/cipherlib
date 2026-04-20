// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../core/cipher.dart';
import '../utils/nonce.dart';
import '../utils/typed_data.dart';

const int _mask32 = 0xFFFFFFFF;

/// Salsa20 is a stream cipher that uses a 256-bit key and a 64-bit nonce to
/// generate a unique cipher stream for each messages.
///
/// This implementation is based on the [Snuffle 2005 specification][spec]
///
/// [spec]: https://cr.yp.to/snuffle/spec.pdf
///
/// See also:
/// - [XSalsa20] for better security with 192-bit nonce
class Salsa20 extends Cipher with SaltedCipher {
  final Uint8List _nonce;

  /// Key for the cipher
  final Uint8List key;

  @override
  String get name => "Salsa20";

  const Salsa20._(
    this.key,
    this._nonce,
  );

  @override
  Uint8List get iv => _nonce;

  /// Creates an instance with a [key], [nonce], and [counter] containing a
  /// list of bytes.
  factory Salsa20(
    List<int> key, [
    List<int>? nonce,
    Nonce64? counter,
  ]) {
    // validate key
    if (key.length != 16 && key.length != 32) {
      throw ArgumentError('The key should be either 16 or 32 bytes');
    }
    final key8 = toUint8List(key);

    // validate nonce
    Uint8List nonce8;
    nonce ??= randomBytes(counter == null ? 16 : 8);
    if (nonce.length == 8) {
      nonce8 = Uint8List(16);
      for (int i = 0; i < 8; ++i) {
        nonce8[i] = nonce[i];
      }
      if (counter != null) {
        for (int i = 0; i < 8; ++i) {
          nonce8[8 + i] = counter.bytes[i];
        }
      }
    } else if (nonce.length == 16) {
      if (counter != null) {
        throw ArgumentError('Counter is not expected with a 16-byte nonce');
      }
      nonce8 = toUint8List(nonce);
    } else {
      throw ArgumentError('The nonce should be either 8 or 16 bytes');
    }

    return Salsa20._(key8, nonce8);
  }

  /// The One-Time-Key used for AEAD cipher
  Uint8List $otk() {
    final state32 = Uint32List(16);
    final key32 = Uint32List.view(key.buffer);
    final nonce32 = Uint32List.view(_nonce.buffer);
    _process(state32, key32, nonce32);
    return Uint8List.view(state32.buffer).sublist(0, 32);
  }

  @override
  Uint8List convert(List<int> message) {
    int i, p, n;
    n = message.length;

    final iv32 = Uint32List(4);
    final result = Uint8List(n);
    final state32 = Uint32List(16);
    final key32 = Uint32List.view(key.buffer);
    final state = Uint8List.view(state32.buffer);
    final nonce32 = Uint32List.view(_nonce.buffer);

    iv32[0] = nonce32[0];
    iv32[1] = nonce32[1];
    iv32[2] = nonce32[2];
    iv32[3] = nonce32[3];

    for (i = 0; i < n;) {
      _process(state32, key32, iv32);
      ++iv32[2];
      if (iv32[2] == 0) {
        ++iv32[3];
      }
      for (p = 0; p < 64 && i < n; ++p, ++i) {
        result[i] = message[i] ^ state[p];
      }
    }
    return result;
  }

  @pragma('vm:prefer-inline')
  static int _rotl32(int x, int n) =>
      (((x << n) & _mask32) ^ ((x & _mask32) >>> (32 - n)));

  static void _process(
    Uint32List input,
    Uint32List key,
    Uint32List nonce, [
    bool hsalsa20 = false,
  ]) {
    int i, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15;

    if (key.lengthInBytes == 16) {
      s0 = input[0] = 0x61707865; // 'expa'
      s1 = input[1] = key[0];
      s2 = input[2] = key[1];
      s3 = input[3] = key[2];
      s4 = input[4] = key[3];
      s5 = input[5] = 0x3120646e; // 'nd 1'
      s6 = input[6] = nonce[0];
      s7 = input[7] = nonce[1];
      s8 = input[8] = nonce[2];
      s9 = input[9] = nonce[3];
      s10 = input[10] = 0x79622d36; // '6-by'
      s11 = input[11] = key[0];
      s12 = input[12] = key[1];
      s13 = input[13] = key[2];
      s14 = input[14] = key[3];
      s15 = input[15] = 0x6b206574; // 'te k'
    } else {
      s0 = input[0] = 0x61707865; // 'expa'
      s1 = input[1] = key[0];
      s2 = input[2] = key[1];
      s3 = input[3] = key[2];
      s4 = input[4] = key[3];
      s5 = input[5] = 0x3320646e; // 'nd 3'
      s6 = input[6] = nonce[0];
      s7 = input[7] = nonce[1];
      s8 = input[8] = nonce[2];
      s9 = input[9] = nonce[3];
      s10 = input[10] = 0x79622d32; // '2-by'
      s11 = input[11] = key[4];
      s12 = input[12] = key[5];
      s13 = input[13] = key[6];
      s14 = input[14] = key[7];
      s15 = input[15] = 0x6b206574; // 'te k'
    }

    // 10 column rounds interleaved with 10 row rounds (20 rounds)
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

    // set result
    if (hsalsa20) {
      input[0] = s0;
      input[1] = s1;
      input[2] = s2;
      input[3] = s3;
      input[4] = s4;
      input[5] = s5;
      input[6] = s6;
      input[7] = s7;
      input[8] = s8;
      input[9] = s9;
      input[10] = s10;
      input[11] = s11;
      input[12] = s12;
      input[13] = s13;
      input[14] = s14;
      input[15] = s15;
    } else {
      input[0] += s0;
      input[1] += s1;
      input[2] += s2;
      input[3] += s3;
      input[4] += s4;
      input[5] += s5;
      input[6] += s6;
      input[7] += s7;
      input[8] += s8;
      input[9] += s9;
      input[10] += s10;
      input[11] += s11;
      input[12] += s12;
      input[13] += s13;
      input[14] += s14;
      input[15] += s15;
    }
  }
}

/// XSalsa20 is a stream cipher that uses a 256-bit key and a 256-bit nonce
/// to generate a unique cipher stream for each messages.
///
/// This implementation is uses [libsodium: core_hsalsa20_ref2.c][git] algorithm
/// for sub-key generation.
///
/// [git]: https://github.com/jedisct1/libsodium/blob/a3d7bc0/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c
///
/// See also:
/// - [Salsa20]
class XSalsa20 extends Salsa20 {
  final Uint8List _xkey;
  final Uint8List _xnonce;
  final Nonce64? _xcounter;

  @override
  String get name => "XSalsa20";

  const XSalsa20._(
    this._xkey,
    this._xnonce,
    this._xcounter,
    Uint8List key,
    Uint8List iv,
  ) : super._(key, iv);

  @override
  Uint8List get iv => _xnonce;

  /// The IV used by the base algorithm
  Uint8List get activeIV => _nonce;

  /// Creates a [XSalsa20] with [key], and [nonce].
  ///
  /// Every elements of the both list is transformed to unsigned 8-bit numbers.
  factory XSalsa20(
    List<int> key, [
    List<int>? nonce,
    Nonce64? counter,
  ]) {
    // validate key
    if (key.length != 16 && key.length != 32) {
      throw ArgumentError('The key should be either 16 or 32 bytes');
    }
    final key8 = toUint8List(key);

    // validate nonce
    nonce ??= randomBytes(32);
    if (nonce.length != 24 && nonce.length != 32) {
      throw ArgumentError('The nonce should be either 24 or 32 bytes');
    }
    if (nonce.length == 32 && counter != null) {
      throw ArgumentError('Counter is not expected with 32-byte nonce');
    }
    final nonce8 = toUint8List(nonce);

    return XSalsa20._(
      key8,
      nonce8,
      counter,
      Uint8List(32),
      Uint8List(16),
    ).._hsalsa20();
  }

  @override
  void resetIV() {
    super.resetIV();
    _hsalsa20();
  }

  void _hsalsa20() {
    // HSalsa20 state from key and first 128-bit of nonce
    var state32 = Uint32List(16);
    var key32 = Uint32List.view(_xkey.buffer);
    var nonce32 = Uint32List.view(_xnonce.buffer);
    Salsa20._process(state32, key32, nonce32, true);

    // Take first 128-bit and last 128-bit from state as subkey
    var subkey32 = Uint32List.fromList([
      state32[0],
      state32[5],
      state32[10],
      state32[15],
      state32[6],
      state32[7],
      state32[8],
      state32[9],
    ]);
    var subkey = Uint8List.view(subkey32.buffer);
    for (int i = 0; i < key.length; i++) {
      key[i] = subkey[i];
    }

    // Use the subkey and last 128-bit of nonce or 96-bit nonce and counter.
    var iv32 = Uint32List.view(_nonce.buffer);
    iv32[0] = nonce32[4];
    iv32[1] = nonce32[5];
    if (_xnonce.length == 32) {
      iv32[2] = nonce32[6];
      iv32[3] = nonce32[7];
    } else if (_xcounter != null) {
      var counter32 = Uint32List.view(_xcounter!.bytes.buffer);
      iv32[2] = counter32[0];
      iv32[3] = counter32[1];
    }
  }
}
