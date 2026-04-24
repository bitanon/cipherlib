// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/random.dart' show randomBytes;

import '../core/cipher.dart';
import '../utils/nonce.dart';
import '../utils/typed_data.dart';

const int _mask32 = 0xFFFFFFFF;

/// ChaCha20 is a stream cipher that uses a 256-bit key and a 64-bit nonce to
/// generate a unique cipher stream for each messages.
///
/// This implementation is based on the [RFC-8439][rfc]
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc8439.html
///
/// See also:
/// - [XChaCha20] for better security with 192-bit nonce
class ChaCha20 extends StreamCipher with SaltedCipher {
  @override
  String get name => "ChaCha20";

  /// Key for the cipher
  final Uint8List key;

  @override
  final Uint8List iv;

  /// The number of bytes from the IV used for the counter
  final int counterBytes;

  const ChaCha20._(
    this.key,
    this.iv, [
    this.counterBytes = 8,
  ]);

  /// Creates an instance with a [key], [nonce], and [counter] containing a
  /// list of bytes.
  ///
  /// Parameters:
  /// - [key] : Either 16 or 32 bytes key.
  /// - [nonce] : Either 8, 12 or 16 bytes nonce. (Default: random)
  /// - [counter] : 64-bit counter. (Default: 1)
  factory ChaCha20(
    List<int> key, [
    List<int>? nonce,
    Nonce64? counter,
  ]) {
    final key8 = validateLength('key', key, {16, 32});

    nonce ??= randomBytes(counter == null ? 16 : 8);
    var nonce8 = toUint8List(nonce);
    int counterSize = nonce8.length == 12 ? 4 : 8;

    if (nonce8.length == 16) {
      if (counter != null) {
        throw ArgumentError.value(
            counter, 'counter', 'not expected with a 16-byte nonce');
      }
    } else if (nonce8.length == 8) {
      nonce8 = Uint8List(16);
      if (counter == null) {
        nonce8[0] = 1;
      } else {
        nonce8[0] = counter.bytes[0];
        nonce8[1] = counter.bytes[1];
        nonce8[2] = counter.bytes[2];
        nonce8[3] = counter.bytes[3];
        nonce8[4] = counter.bytes[4];
        nonce8[5] = counter.bytes[5];
        nonce8[6] = counter.bytes[6];
        nonce8[7] = counter.bytes[7];
      }
      nonce8[8] = nonce[0];
      nonce8[9] = nonce[1];
      nonce8[10] = nonce[2];
      nonce8[11] = nonce[3];
      nonce8[12] = nonce[4];
      nonce8[13] = nonce[5];
      nonce8[14] = nonce[6];
      nonce8[15] = nonce[7];
    } else if (nonce8.length == 12) {
      nonce8 = Uint8List(16);
      if (counter == null) {
        nonce8[0] = 1;
      } else {
        nonce8[0] = counter.bytes[0];
        nonce8[1] = counter.bytes[1];
        nonce8[2] = counter.bytes[2];
        nonce8[3] = counter.bytes[3];
      }
      nonce8[4] = nonce[0];
      nonce8[5] = nonce[1];
      nonce8[6] = nonce[2];
      nonce8[7] = nonce[3];
      nonce8[8] = nonce[4];
      nonce8[9] = nonce[5];
      nonce8[10] = nonce[6];
      nonce8[11] = nonce[7];
      nonce8[12] = nonce[8];
      nonce8[13] = nonce[9];
      nonce8[14] = nonce[10];
      nonce8[15] = nonce[11];
    } else {
      throw ArgumentError.value(
          nonce, 'nonce', 'length must be one of [8, 12, 16] bytes');
    }

    return ChaCha20._(key8, nonce8, counterSize);
  }

  /// The One-Time-Key used for AEAD cipher
  Uint8List $otk() {
    var state32 = Uint32List(16);
    var key32 = Uint32List.view(key.buffer);
    var iv32 = Uint32List.view(iv.buffer);
    var nonce32 = Uint32List(4);
    if (counterBytes == 4) {
      nonce32[1] = iv32[1];
    }
    nonce32[2] = iv32[2];
    nonce32[3] = iv32[3];
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
    final state = Uint8List.view(state32.buffer);
    final key32 = Uint32List.view(key.buffer);
    final nonce32 = Uint32List.view(iv.buffer);

    iv32[0] = nonce32[0];
    iv32[1] = nonce32[1];
    iv32[2] = nonce32[2];
    iv32[3] = nonce32[3];

    for (i = 0; i < message.length;) {
      _process(state32, key32, iv32);
      _increment(iv32, counterBytes);
      for (p = 0; p < 64 && i < message.length; ++p, ++i) {
        result[i] = message[i] ^ state[p];
      }
    }

    return result;
  }

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) async* {
    int i, p, n;

    final iv32 = Uint32List(4);
    final result = Uint8List(64);
    final state32 = Uint32List(16);
    final key32 = Uint32List.view(key.buffer);
    final state = Uint8List.view(state32.buffer);
    final nonce32 = Uint32List.view(iv.buffer);

    iv32[0] = nonce32[0];
    iv32[1] = nonce32[1];
    iv32[2] = nonce32[2];
    iv32[3] = nonce32[3];

    p = 0;
    _process(state32, key32, iv32);
    _increment(iv32, counterBytes);
    await for (final chunk in stream) {
      n = chunk.length;
      for (i = 0; i < n;) {
        for (; p < 64 && i < n; p++, i++) {
          result[p] = chunk[i] ^ state[p];
        }
        if (p == 64) {
          _process(state32, key32, iv32);
          _increment(iv32, counterBytes);
          yield result.sublist(0);
          p = 0;
        }
      }
    }
    if (p > 0) {
      yield result.sublist(0, p);
    }
  }

  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  static int _rotl32(int x, int n) =>
      (((x << n) & _mask32) ^ ((x & _mask32) >>> (32 - n)));

  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  static void _increment(Uint32List iv32, int counterBytes) {
    iv32[0]++;
    if (iv32[0] == 0 && counterBytes == 8) {
      iv32[1]++;
    }
  }

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

/// XChaCha20 is a stream cipher that uses a 256-bit key and a 192-bit nonce
/// to generate a unique cipher stream for each messages.
///
/// This implementation is based on the [draft-irtf-cfrg-xchacha-03][rfc]
///
/// [rfc]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
///
/// See also:
/// - [ChaCha20]
class XChaCha20 extends StreamCipher with SaltedCipher {
  @override
  String get name => "XChaCha20";

  /// The internal ChaCha20 cipher instance
  final ChaCha20 internal;

  /// The key used by the XChaCha20 algorithm
  final Uint8List key;

  @override
  final Uint8List iv;

  /// The counter used by the XChaCha20 algorithm
  final Nonce64? counter;

  const XChaCha20._(
    this.key,
    this.iv,
    this.counter,
    this.internal,
  );

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

    final key8 = toUint8List(key);
    final nonce8 = toUint8List(nonce);
    final internal = ChaCha20._(Uint8List(32), Uint8List(16), counterSize);

    return XChaCha20._(
      key8,
      nonce8,
      counter,
      internal,
    ).._hchacha20();
  }

  /// Key used by the internal ChaCha20 cipher instance
  Uint8List get subkey => internal.key;

  /// IV used by the internal ChaCha20 cipher instance
  Uint8List get subnonce => internal.iv;

  /// The One-Time-Key used for AEAD cipher
  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  Uint8List $otk() => internal.$otk();

  @override
  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  Uint8List convert(List<int> message) => internal.convert(message);

  @override
  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  Stream<Uint8List> bind(Stream<List<int>> stream) => internal.bind(stream);

  @override
  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  void resetIV() {
    super.resetIV();
    _hchacha20();
  }

  void _hchacha20() {
    // HChaCha20 State from key and first 16 byte of nonce
    final state32 = Uint32List(16);
    final xkey32 = Uint32List.view(key.buffer);
    final xnonce32 = Uint32List.view(iv.buffer);
    final iv32 = Uint32List.view(internal.iv.buffer);
    final key32 = Uint32List.view(internal.key.buffer);
    ChaCha20._process(state32, xkey32, xnonce32, true);

    // Take first 128-bit and last 128-bit from state as subkey
    key32[0] = state32[0];
    key32[1] = state32[1];
    key32[2] = state32[2];
    key32[3] = state32[3];
    key32[4] = state32[12];
    key32[5] = state32[13];
    key32[6] = state32[14];
    key32[7] = state32[15];

    // Use the subkey and remaining 8 byte of nonce
    if (iv.length == 32) {
      iv32[0] = xnonce32[4];
      iv32[1] = xnonce32[5];
      iv32[2] = xnonce32[6];
      iv32[3] = xnonce32[7];
    } else {
      if (counter == null) {
        iv32[0] = 1;
        iv32[1] = 0;
      } else {
        final counter32 = Uint32List.view(counter!.bytes.buffer);
        iv32[0] = counter32[0];
        iv32[1] = counter32[1];
      }
      if (iv.length == 28) {
        iv32[1] = xnonce32[4];
        iv32[2] = xnonce32[5];
        iv32[3] = xnonce32[6];
      } else {
        iv32[2] = xnonce32[4];
        iv32[3] = xnonce32[5];
      }
    }
  }
}
