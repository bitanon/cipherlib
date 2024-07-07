// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:cipherlib/src/core/collate_cipher.dart';
import 'package:cipherlib/src/core/salted_cipher.dart';
import 'package:hashlib/hashlib.dart';

import '_core.dart';

/// The sink used for encryption by the [AESInCFBModeEncrypt] algorithm.
class AESInCFBModeEncryptSink extends CipherSink {
  AESInCFBModeEncryptSink(
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
  late final Uint32List _key32 = Uint32List.view(_key.buffer);
  final int _sbyte;
  final _salt = Uint8List(16);
  final _block = Uint8List(16); // 128-bit
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
    int start = 0,
    int? end,
    bool last = false,
  ]) {
    if (_closed) {
      throw StateError('The sink is closed');
    }
    _closed = last;
    end ??= data.length;

    int i, j;
    j = _pos + 16 - _sbyte;
    var output = Uint8List(end - start);
    for (i = start; i < end; ++i) {
      if (_pos == 0) {
        for (j = 0; j < 16; ++j) {
          _block[j] = _salt[j];
        }
        AESCore.$encrypt(_block32, _xkey32);
        for (j = _sbyte; j < 16; ++j) {
          _salt[j - _sbyte] = _salt[j];
        }
        j = 16 - _sbyte;
      }
      output[i] = _block[_pos++] ^ data[i];
      _salt[j++] = output[i];
      if (_pos == _sbyte) {
        _pos = 0;
      }
    }

    return output;
  }
}

/// The sink used for decryption by the [AESInCFBModeDecrypt] algorithm.
class AESInCFBModeDecryptSink extends CipherSink {
  AESInCFBModeDecryptSink(
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
  late final Uint32List _key32 = Uint32List.view(_key.buffer);
  final int _sbyte;
  final _block = Uint8List(16); // 128-bit
  final _salt = Uint8List(16);
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
    int start = 0,
    int? end,
    bool last = false,
  ]) {
    if (_closed) {
      throw StateError('The sink is closed');
    }
    _closed = last;
    end ??= data.length;

    int i, j;
    j = _pos + 16 - _sbyte;
    var output = Uint8List(end - start);
    for (i = start; i < end; ++i) {
      if (_pos == 0) {
        for (j = 0; j < 16; ++j) {
          _block[j] = _salt[j];
        }
        AESCore.$encrypt(_block32, _xkey32);
        for (j = _sbyte; j < 16; ++j) {
          _salt[j - _sbyte] = _salt[j];
        }
        j = 16 - _sbyte;
      }
      output[i] = _block[_pos++] ^ data[i];
      _salt[j++] = data[i];
      if (_pos == _sbyte) {
        _pos = 0;
      }
    }

    return output;
  }
}

/// Provides encryption for AES cipher in CFB mode.
class AESInCFBModeEncrypt extends SaltedCipher {
  @override
  String get name => "AES#encrypt/CFB";

  /// Key for the cipher
  final Uint8List key;

  /// Number of bytes to use per block
  final int sbyte;

  const AESInCFBModeEncrypt(
    this.key,
    Uint8List iv,
    this.sbyte,
  ) : super(iv);

  @override
  @pragma('vm:prefer-inline')
  AESInCFBModeEncryptSink createSink() =>
      AESInCFBModeEncryptSink(key, iv, sbyte);
}

/// Provides decryption for AES cipher in CFB mode.
class AESInCFBModeDecrypt extends SaltedCipher {
  @override
  String get name => "AES#decrypt/CFB";

  /// Key for the cipher
  final Uint8List key;

  /// Number of bytes to use per block
  final int sbyte;

  const AESInCFBModeDecrypt(this.key, Uint8List iv, this.sbyte) : super(iv);

  @override
  @pragma('vm:prefer-inline')
  AESInCFBModeDecryptSink createSink() =>
      AESInCFBModeDecryptSink(key, iv, sbyte);
}

/// Provides encryption and decryption for AES cipher in CFB mode.
class AESInCFBMode extends CollateCipher {
  @override
  String get name => "AES/CFB";

  @override
  final AESInCFBModeEncrypt encryptor;

  @override
  final AESInCFBModeDecrypt decryptor;

  const AESInCFBMode._({
    required this.encryptor,
    required this.decryptor,
  });

  /// Creates a AES cipher in CFB mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit random initialization vector or salt
  /// - [sbyte] number of bits to take per block to encrypt plaintext.
  factory AESInCFBMode(
    List<int> key, {
    List<int>? iv,
    int sbyte = 8,
  }) {
    iv ??= randomBytes(16);
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    if (sbyte < 1 || sbyte > 16) {
      throw StateError('sbyte must be between 1 and 16');
    }
    if (iv8.lengthInBytes < 16) {
      throw StateError('IV must be at least 16-bytes');
    }
    return AESInCFBMode._(
      encryptor: AESInCFBModeEncrypt(key8, iv8, sbyte),
      decryptor: AESInCFBModeDecrypt(key8, iv8, sbyte),
    );
  }

  /// IV for the cipher
  Uint8List get iv => encryptor.iv;

  /// Replaces current IV with a new random one
  @pragma('vm:prefer-inline')
  void resetIV() => fillRandom(iv.buffer);
}
