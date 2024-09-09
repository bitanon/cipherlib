// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:cipherlib/src/core/salted_cipher.dart';
import 'package:cipherlib/src/utils/nonce.dart';
import 'package:hashlib/hashlib.dart' show randomBytes;

const int _mask32 = 0xFFFFFFFF;

/// This sink is used by the [ChaCha20] algorithm.
class ChaCha20Sink implements CipherSink {
  ChaCha20Sink(this._key, this._nonce, this._counterBytes) {
    reset();
  }

  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;
  final Uint8List _nonce;
  final int _counterBytes;
  final _iv32 = Uint32List(4);
  final _state32 = Uint32List(16);
  late final _state = Uint8List.view(_state32.buffer);
  late final _key32 = Uint32List.view(_key.buffer);
  late final _nonce32 = Uint32List.view(_nonce.buffer);

  @override
  bool get closed => _closed;

  @override
  void reset() {
    _pos = 0;
    _closed = false;
    _iv32[0] = _nonce32[0];
    _iv32[1] = _nonce32[1];
    _iv32[2] = _nonce32[2];
    _iv32[3] = _nonce32[3];
  }

  @override
  Uint8List add(
    List<int> data, [
    bool last = false,
    int start = 0,
    int? end,
  ]) {
    if (_closed) {
      throw StateError('The sink is closed');
    }
    _closed = last;
    end ??= data.length;

    var result = Uint8List(end - start);
    for (int i = start; i < end; i++) {
      if (_pos == 0) {
        _process(_state32, _key32, _iv32);
        if ((++_iv32[0]) == 0 && _counterBytes == 8) {
          ++_iv32[1];
        }
      }
      result[i] = data[i] ^ _state[_pos];
      _pos = (_pos + 1) & 63;
    }
    return result;
  }

  @override
  @pragma('vm:prefer-inline')
  Uint8List close() {
    _closed = true;
    return Uint8List(0);
  }

  @pragma('vm:prefer-inline')
  static int _rotl32(int x, int n) =>
      (((x << n) & _mask32) ^ ((x & _mask32) >>> (32 - n)));

  static void _process(
    Uint32List input,
    Uint32List key,
    Uint32List nonce, [
    bool hchacha20 = false,
  ]) {
    int i, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15;

    // init state
    if (key.lengthInBytes == 16) {
      s0 = input[0] = 0x61707865; // 'expa'
      s1 = input[1] = 0x3120646e; // 'nd 1'
      s2 = input[2] = 0x79622d36; // '6-by'
      s3 = input[3] = 0x6b206574; // 'te k
      s4 = input[4] = key[0];
      s5 = input[5] = key[1];
      s6 = input[6] = key[2];
      s7 = input[7] = key[3];
      s8 = input[8] = key[0];
      s9 = input[9] = key[1];
      s10 = input[10] = key[2];
      s11 = input[11] = key[3];
      s12 = input[12] = nonce[0];
      s13 = input[13] = nonce[1];
      s14 = input[14] = nonce[2];
      s15 = input[15] = nonce[3];
    } else {
      s0 = input[0] = 0x61707865; // 'expa'
      s1 = input[1] = 0x3320646e; // 'nd 3'
      s2 = input[2] = 0x79622d32; // '2-by'
      s3 = input[3] = 0x6b206574; // 'te k
      s4 = input[4] = key[0];
      s5 = input[5] = key[1];
      s6 = input[6] = key[2];
      s7 = input[7] = key[3];
      s8 = input[8] = key[4];
      s9 = input[9] = key[5];
      s10 = input[10] = key[6];
      s11 = input[11] = key[7];
      s12 = input[12] = nonce[0];
      s13 = input[13] = nonce[1];
      s14 = input[14] = nonce[2];
      s15 = input[15] = nonce[3];
    }

    // 10 column rounds interleaved with 10 diagonal rounds (20 rounds)
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

    // set result
    if (hchacha20) {
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

/// ChaCha20 is a stream cipher that uses a 256-bit key and a 64-bit nonce to
/// generate a unique cipher stream for each messages.
///
/// This implementation is based on the [RFC-8439][rfc]
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc8439.html
///
/// See also:
/// - [XChaCha20] for better security with 192-bit nonce
class ChaCha20 extends SaltedCipher {
  final int _counterBytes;

  @override
  String get name => "ChaCha20";

  /// Key for the cipher
  final Uint8List key;

  const ChaCha20._(
    this.key,
    Uint8List nonce, [
    this._counterBytes = 8,
  ]) : super(nonce);

  @override
  @pragma('vm:prefer-inline')
  CipherSink createSink() => ChaCha20Sink(key, iv, _counterBytes);

  /// Creates an instance with a [key], [nonce], and [counter] containing a
  /// list of bytes.
  factory ChaCha20(
    List<int> key, [
    List<int>? nonce,
    Nonce64? counter,
  ]) {
    // validate ley
    if (key.length != 16 && key.length != 32) {
      throw ArgumentError('The key should be either 16 or 32 bytes');
    }
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);

    // validate nonce
    Uint8List nonce8;
    int counterSize = 8;
    nonce ??= randomBytes(8);
    if (nonce.length == 8) {
      nonce8 = Uint8List(16);
      if (counter == null) {
        nonce8[0] = 1;
      } else {
        nonce8.setAll(0, counter.bytes);
      }
      nonce8.setAll(8, nonce);
    } else if (nonce.length == 12) {
      counterSize = 4;
      nonce8 = Uint8List(16);
      if (counter == null) {
        nonce8[0] = 1;
      } else {
        nonce8.setAll(0, counter.bytes);
      }
      nonce8.setAll(4, nonce);
    } else if (nonce.length == 16) {
      if (counter != null) {
        throw ArgumentError('Counter is not expected with 16-byte nonce');
      }
      nonce8 = nonce is Uint8List ? nonce : Uint8List.fromList(nonce);
    } else {
      throw ArgumentError('The nonce should be either 8, 12 or 16 bytes');
    }

    return ChaCha20._(key8, nonce8, counterSize);
  }

  /// The One-Time-Key used for AEAD cipher
  Uint8List $otk() {
    var state32 = Uint32List(16);
    var state = Uint8List.view(state32.buffer);
    var key32 = Uint32List.view(key.buffer);
    var iv32 = Uint32List.view(iv.buffer);
    var nonce32 = Uint32List(4);
    if (_counterBytes == 4) {
      nonce32[1] = iv32[1];
    }
    nonce32[2] = iv32[2];
    nonce32[3] = iv32[3];
    ChaCha20Sink._process(state32, key32, nonce32);
    return state.sublist(0, 32);
  }
}

/// XChaCha20 is a stream cipher that uses a 256-bit key and a 192-bit nonce
/// to generate a unique cipher stream for each messages.
///
/// This implementation is based on the [draft-irtf-cfrg-xchacha-03][rfc]
///
/// [rfc]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
///
/// See also:
/// - [ChaCha20]
class XChaCha20 extends ChaCha20 {
  @override
  String get name => "XChaCha20";

  const XChaCha20._(
    Uint8List key,
    Uint8List nonce, [
    int counterBytes = 8,
  ]) : super._(key, nonce, counterBytes);

  /// Creates a [XChaCha20] with [key], and [nonce].
  ///
  /// Every elements of the both list is transformed to unsigned 8-bit numbers.
  factory XChaCha20(
    List<int> key, [
    List<int>? nonce,
    Nonce64? counter,
  ]) {
    // validate key
    if (key.length != 16 && key.length != 32) {
      throw ArgumentError('The key should be either 16 or 32 bytes');
    }
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);

    // validate nonce
    int counterSize = 8;
    nonce ??= randomBytes(24);
    if (nonce.length == 28) {
      counterSize = 4;
    } else if (nonce.length == 32) {
      if (counter != null) {
        throw ArgumentError('Counter is not expected with 32-byte nonce');
      }
    } else if (nonce.length != 24) {
      throw ArgumentError('The nonce should be either 24, 28 or 32 bytes');
    }
    var nonce8 = nonce is Uint8List ? nonce : Uint8List.fromList(nonce);

    // HChaCha20 State from key and first 16 byte of nonce
    var state32 = Uint32List(16);
    var key32 = Uint32List.view(key8.buffer);
    var nonce32 = Uint32List.view(nonce8.buffer);
    ChaCha20Sink._process(state32, key32, nonce32, true);

    // Take first 128-bit and last 128-bit from state as subkey
    var subkey32 = Uint32List.fromList([
      state32[0],
      state32[1],
      state32[2],
      state32[3],
      state32[12],
      state32[13],
      state32[14],
      state32[15],
    ]);

    // Use the subkey and remaining 8 byte of nonce
    var subkey = Uint8List.view(subkey32.buffer);
    var iv32 = Uint32List(4);
    var iv = Uint8List.view(iv32.buffer);
    iv32[2] = nonce32[4];
    iv32[3] = nonce32[5];
    if (nonce.length == 28) {
      iv32[1] = nonce32[4];
      iv32[2] = nonce32[5];
      iv32[3] = nonce32[6];
    } else if (nonce.length == 32) {
      iv32[0] = nonce32[4];
      iv32[1] = nonce32[5];
      iv32[2] = nonce32[6];
      iv32[3] = nonce32[7];
    }
    if (counter == null) {
      iv[0] = 1;
    } else {
      var counter32 = Uint32List.view(counter.bytes.buffer);
      iv32[0] = counter32[0];
      if (counterSize == 8) {
        iv32[1] = counter32[1];
      }
    }
    return XChaCha20._(subkey, iv, counterSize);
  }
}
