// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../../core/cipher.dart';
import '../../core/cipher_sink.dart';
import '../../core/collate_cipher.dart';
import '../aes.dart';
import '../padding.dart';

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
  final Uint8List _key;
  final Uint8List _iv;
  final int _sbyte;
  final _salt = Uint8List(16);
  final _block = Uint8List(16); // 128-bit
  late final _key32 = Uint32List.view(_key.buffer);
  late final _block32 = Uint32List.view(_block.buffer);
  late final _xkey32 = AESCore.$expandEncryptionKey(_key32);

  @override
  void reset() {
    super.reset();
    _pos = 0;
    for (int i = 0; i < 16; ++i) {
      _salt[i] = _iv[i];
    }
  }

  @override
  @pragma('vm:prefer-inline')
  Uint8List $add(List<int> data, int start, int end) {
    int i, j, p;
    var output = Uint8List(end - start);

    p = 0;
    j = _pos + 16 - _sbyte;
    for (i = start; i < end; ++i) {
      if (_pos == 0) {
        for (j = 0; j < 16; ++j) {
          _block[j] = _salt[j];
        }
        AESCore.$encryptLE(_block32, _xkey32);
        for (j = _sbyte; j < 16; ++j) {
          _salt[j - _sbyte] = _salt[j];
        }
        j = 16 - _sbyte;
      }
      output[p] = _block[_pos++] ^ data[i];
      _salt[j++] = output[p++];
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
  final Uint8List _key;
  final Uint8List _iv;
  late final Uint32List _key32 = Uint32List.view(_key.buffer);
  final int _sbyte;
  final _block = Uint8List(16); // 128-bit
  final _salt = Uint8List(16);
  late final _block32 = Uint32List.view(_block.buffer);
  late final _xkey32 = AESCore.$expandEncryptionKey(_key32);

  @override
  void reset() {
    super.reset();
    _pos = 0;
    for (int i = 0; i < 16; ++i) {
      _salt[i] = _iv[i];
    }
  }

  @override
  @pragma('vm:prefer-inline')
  Uint8List $add(List<int> data, int start, int end) {
    int i, j, p;
    p = 0;
    j = _pos + 16 - _sbyte;
    var output = Uint8List(end - start);
    for (i = start; i < end; ++i) {
      if (_pos == 0) {
        for (j = 0; j < 16; ++j) {
          _block[j] = _salt[j];
        }
        AESCore.$encryptLE(_block32, _xkey32);
        for (j = _sbyte; j < 16; ++j) {
          _salt[j - _sbyte] = _salt[j];
        }
        j = 16 - _sbyte;
      }
      output[p++] = _block[_pos++] ^ data[i];
      _salt[j++] = data[i];
      if (_pos == _sbyte) {
        _pos = 0;
      }
    }

    return output;
  }
}

/// Provides encryption for AES cipher in CFB mode.
class AESInCFBModeEncrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#encrypt/CFB/${Padding.none.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Number of bytes to use per block
  final int sbyte;

  @override
  final Uint8List iv;

  const AESInCFBModeEncrypt(
    this.key,
    this.iv,
    this.sbyte,
  );

  @override
  @pragma('vm:prefer-inline')
  AESInCFBModeEncryptSink createSink() =>
      AESInCFBModeEncryptSink(key, iv, sbyte);
}

/// Provides decryption for AES cipher in CFB mode.
class AESInCFBModeDecrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#decrypt/CFB/${Padding.none.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Number of bytes to use per block
  final int sbyte;

  @override
  final Uint8List iv;

  const AESInCFBModeDecrypt(
    this.key,
    this.iv,
    this.sbyte,
  );

  @override
  @pragma('vm:prefer-inline')
  AESInCFBModeDecryptSink createSink() =>
      AESInCFBModeDecryptSink(key, iv, sbyte);
}

/// Provides encryption and decryption for AES cipher in CFB mode.
class AESInCFBMode extends CollateCipher with SaltedCipher {
  @override
  String get name => "AES/CFB/${Padding.none.name}";

  @override
  final AESInCFBModeEncrypt encryptor;

  @override
  final AESInCFBModeDecrypt decryptor;

  const AESInCFBMode._({
    required this.encryptor,
    required this.decryptor,
  });

  @override
  Uint8List get iv => encryptor.iv;

  /// Creates AES cipher in CFB mode.
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
    if (sbyte < 1 || sbyte > 16) {
      throw StateError('sbyte must be between 1 and 16');
    }
    iv ??= randomBytes(16);
    if (iv.length < 16) {
      throw StateError('IV must be at least 16-bytes');
    }
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    return AESInCFBMode._(
      encryptor: AESInCFBModeEncrypt(key8, iv8, sbyte),
      decryptor: AESInCFBModeDecrypt(key8, iv8, sbyte),
    );
  }
}
