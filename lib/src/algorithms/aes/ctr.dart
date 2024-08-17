// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/padding.dart';
import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:cipherlib/src/core/salted_cipher.dart';
import 'package:cipherlib/src/utils/nonce.dart';
import 'package:hashlib/hashlib.dart' show randomBytes;

import '_core.dart';

const int _mask32 = 0xFFFFFFFF;

@pragma('vm:prefer-inline')
int _swap32(int x) =>
    ((x << 24) & 0xff000000) |
    ((x << 8) & 0x00ff0000) |
    ((x >>> 8) & 0x0000ff00) |
    ((x >>> 24) & 0x000000ff);

/// The sink used for both encryption and decryption by the
/// [AESInCTRModeCipher] algorithm.
class AESInCTRModeSink extends CipherSink {
  AESInCTRModeSink(
    this._key,
    this._iv,
  ) {
    reset();
  }

  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;
  final Uint8List _iv;
  late int _s0, _s1, _s2, _s3;
  final _block32 = Uint32List(4); // 128-bit
  late final _key32 = Uint32List.view(_key.buffer);
  late final _block = Uint8List.view(_block32.buffer);
  late final _xkey32 = AESCore.$expandEncryptionKey(_key32);

  @override
  bool get closed => _closed;

  @override
  void reset() {
    _pos = 0;
    _closed = false;
    _s0 = (_iv[0] << 24) | (_iv[1] << 16) | (_iv[2] << 8) | (_iv[3]);
    _s1 = (_iv[4] << 24) | (_iv[5] << 16) | (_iv[6] << 8) | (_iv[7]);
    _s2 = (_iv[8] << 24) | (_iv[9] << 16) | (_iv[10] << 8) | (_iv[11]);
    _s3 = (_iv[12] << 24) | (_iv[13] << 16) | (_iv[14] << 8) | (_iv[15]);
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

    int i, p;
    var output = Uint8List(end - start);

    p = 0;
    for (i = start; i < end; ++i) {
      if (_pos == 0) {
        _block32[0] = _s0;
        _block32[1] = _s1;
        _block32[2] = _s2;
        _block32[3] = _s3;
        AESCore.$encrypt(_block32, _xkey32);
        _block32[0] = _swap32(_block32[0]);
        _block32[1] = _swap32(_block32[1]);
        _block32[2] = _swap32(_block32[2]);
        _block32[3] = _swap32(_block32[3]);
        _s3 = (_s3 + 1) & _mask32;
        if (_s3 == 0) {
          _s2 = (_s2 + 1) & _mask32;
        }
      }
      output[p++] = _block[_pos] ^ data[i];
      _pos = (_pos + 1) & 15;
    }

    return output;
  }
}

/// Provides AES cipher in CTR mode.
class AESInCTRModeCipher extends SaltedCipher {
  @override
  String get name => "AES#cipher/CTR/${Padding.none.name}";

  /// Key for the cipher
  final Uint8List key;

  const AESInCTRModeCipher(this.key, Uint8List iv) : super(iv);

  @override
  @pragma('vm:prefer-inline')
  AESInCTRModeSink createSink() => AESInCTRModeSink(key, iv);
}

/// Provides encryption and decryption for AES cipher in CTR mode.
class AESInCTRMode extends SaltedCollateCipher {
  @override
  String get name => "AES/CTR/${Padding.none.name}";

  @override
  final AESInCTRModeCipher encryptor;

  @override
  final AESInCTRModeCipher decryptor;

  const AESInCTRMode._({
    required this.encryptor,
    required this.decryptor,
  });

  /// Creates AES cipher in CTR mode.
  ///
  /// The [iv] parameter combines the 64-bit nonce, and 64-bit counter
  /// value together to make a 128-bit initialization vector for the algorithm.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit random initialization vector or salt
  factory AESInCTRMode(List<int> key, [List<int>? iv]) {
    iv ??= randomBytes(16);
    if (iv.length < 16) {
      throw StateError('IV must be at least 16-bytes');
    }
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    var cipher = AESInCTRModeCipher(key8, iv8);
    return AESInCTRMode._(
      encryptor: cipher,
      decryptor: cipher,
    );
  }

  /// Creates AES cipher in CTR mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [nonce] 64-bit random integer nonce
  /// - [counter] 64-bit random integer counter
  factory AESInCTRMode.nonce(
    List<int> key, {
    Nonce64? nonce,
    Nonce64? counter,
  }) {
    var nonce8 = (nonce?.reverse() ?? Nonce64.random()).bytes;
    var counter8 = (counter?.reverse() ?? Nonce64.random()).bytes;
    var iv = Uint8List.fromList([...nonce8, ...counter8]);
    return AESInCTRMode(key, iv);
  }
}
