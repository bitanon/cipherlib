// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';
import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:cipherlib/src/core/collate_cipher.dart';
import 'package:hashlib/hashlib.dart' show randomBytes;

import '../padding.dart';
import '_core.dart';

/// The sink used for encryption by the [AESInOFBModeCipher] algorithm.
class AESInOFBModeSink implements CipherSink {
  AESInOFBModeSink(
    this._key,
    this._iv,
    this._sbyte,
  ) {
    reset();
  }

  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;
  final Uint8List _iv;
  final int _sbyte;
  final _salt = Uint8List(16);
  final _block = Uint8List(16); // 128-bit
  late final _key32 = Uint32List.view(_key.buffer);
  late final _block32 = Uint32List.view(_block.buffer);
  late final _xkey32 = AESCore.$expandEncryptionKey(_key32);

  @override
  bool get closed => _closed;

  @override
  void reset() {
    _pos = 0;
    _closed = false;
    for (int i = 0; i < 16; ++i) {
      _salt[i] = _iv[i];
    }
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

    int i, j, p;
    var output = Uint8List(end - start);

    p = 0;
    for (i = start; i < end; ++i) {
      if (_pos == 0) {
        for (j = 0; j < 16; ++j) {
          _block[j] = _salt[j];
        }
        AESCore.$encryptLE(_block32, _xkey32);
        for (j = _sbyte; j < 16; ++j) {
          _salt[j - _sbyte] = _salt[j];
        }
        for (j = 0; j < _sbyte; ++j) {
          _salt[16 - _sbyte + j] = _block[j];
        }
      }
      output[p++] = _block[_pos++] ^ data[i];
      if (_pos == _sbyte) {
        _pos = 0;
      }
    }

    return output;
  }

  @override
  @pragma('vm:prefer-inline')
  Uint8List close() => add([], true);
}

/// Provides encryption for AES cipher in OFB mode.
class AESInOFBModeCipher extends Cipher with SaltedCipher {
  @override
  String get name => "AES#cipher/OFB/${Padding.none.name}";

  /// Key for the cipher
  final Uint8List key;

  @override
  final Uint8List iv;

  /// Number of bytes to use per block
  final int sbyte;

  const AESInOFBModeCipher(
    this.key,
    this.iv,
    this.sbyte,
  );

  @override
  @pragma('vm:prefer-inline')
  AESInOFBModeSink createSink() => AESInOFBModeSink(key, iv, sbyte);
}

/// Provides encryption and decryption for AES cipher in OFB mode.
class AESInOFBMode extends CollateCipher with SaltedCipher {
  @override
  String get name => "AES/OFB/${Padding.none.name}";

  @override
  final AESInOFBModeCipher encryptor;

  @override
  final AESInOFBModeCipher decryptor;

  const AESInOFBMode._({
    required this.encryptor,
    required this.decryptor,
  });

  @override
  Uint8List get iv => encryptor.iv;

  /// Creates AES cipher in OFB mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit random initialization vector or salt
  factory AESInOFBMode(
    List<int> key, {
    List<int>? iv,
    int sbyte = 8,
  }) {
    iv ??= randomBytes(16);
    if (iv.length < 16) {
      throw StateError('IV must be at least 16-bytes');
    }
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    var cipher = AESInOFBModeCipher(key8, iv8, sbyte);
    return AESInOFBMode._(
      encryptor: cipher,
      decryptor: cipher,
    );
  }
}
