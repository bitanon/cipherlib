// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';
import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:cipherlib/src/core/collate_cipher.dart';
import 'package:hashlib/random.dart' show randomBytes;

import '../padding.dart';
import '_core.dart';

/// The sink used for encryption by the [AESInIGEModeEncrypt] algorithm.
class AESInIGEModeEncryptSink implements CipherSink {
  AESInIGEModeEncryptSink(
    this._key,
    this._iv,
    this._padding,
  ) {
    reset();
  }

  int _pos = 0;
  bool _closed = false;
  final Uint8List _iv;
  final Uint8List _key;
  final Padding _padding;
  final _block = Uint8List(16); // 128-bit
  final _salt = Uint8List(32);
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
      _block[i] = _iv[i]; // iv1
      _salt[i] = 0;
      _salt[i + 16] = 0;
    }
    for (int i = 16; i < _iv.length && i < 32; ++i) {
      _salt[i - 16] = _iv[i]; // iv2
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

    int i, j, p, n;

    n = _pos + end - start;
    if (last) {
      n += 16 - (n & 15);
    }
    var output = Uint8List(n);

    p = 0;
    for (i = start; i < end; ++i) {
      _salt[_pos + 16] = data[i];
      _block[_pos++] ^= data[i];
      if (_pos == 16) {
        AESCore.$encryptLE(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          _block[j] ^= _salt[j];
          _salt[j] = _salt[j + 16];
          output[p++] = _block[j];
        }
        _pos = 0;
      }
    }

    if (last) {
      if (_padding.pad(_salt, _pos + 16)) {
        for (; _pos < 16; _pos++) {
          _block[_pos] ^= _salt[_pos + 16];
        }
        AESCore.$encryptLE(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          output[p++] = _block[j] ^ _salt[j];
        }
        _pos = 0;
      }
      if (_pos != 0) {
        throw StateError('Invalid input size');
      }
    }

    if (n == p) {
      return output;
    } else if (p == 0) {
      return Uint8List(0);
    } else {
      return output.sublist(0, p);
    }
  }

  @override
  @pragma('vm:prefer-inline')
  Uint8List close() => add([], true);
}

/// The sink used for decryption by the [AESInIGEModeDecrypt] algorithm.
class AESInIGEModeDecryptSink implements CipherSink {
  AESInIGEModeDecryptSink(
    this._key,
    this._iv,
    this._padding,
  ) {
    reset();
  }

  int _pos = 0;
  int _rpos = 0;
  bool _closed = false;
  final Uint8List _key;
  final Uint8List _iv;
  final Padding _padding;
  late final Uint32List _key32 = Uint32List.view(_key.buffer);
  final _block = Uint8List(16); // 128-bit
  final _salt = Uint8List(32);
  final _residue = Uint8List(16);
  late final _block32 = Uint32List.view(_block.buffer);
  late final _xkey32 = AESCore.$expandDecryptionKey(_key32);

  @override
  bool get closed => _closed;

  @override
  void reset() {
    _pos = 0;
    _rpos = 0;
    _closed = false;
    for (int i = 0; i < 16; ++i) {
      _block[i] = 0;
      _salt[i] = _iv[i]; // iv1
      _salt[i + 16] = 0;
    }
    for (int i = 16; i < _iv.length && i < 32; ++i) {
      _block[i - 16] = _iv[i]; //iv2
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

    int i, j, k, p, n;

    n = _rpos + end - start;
    var output = Uint8List(n);

    p = 0;
    for (i = start; i < end; ++i) {
      _salt[_pos + 16] = data[i];
      _block[_pos++] ^= data[i];
      if (_pos == 16) {
        AESCore.$decryptLE(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          if (_rpos == 16) {
            for (k = 0; k < 16; ++k) {
              output[p++] = _residue[k];
            }
            _rpos = 0;
          }
          _block[j] ^= _salt[j];
          _salt[j] = _salt[j + 16];
          _residue[_rpos++] = _block[j];
        }
        _pos = 0;
      }
    }

    if (last) {
      if (_rpos == 16) {
        for (k = 0; k < 16; ++k) {
          output[p++] = _residue[k];
        }
        _rpos = 0;
      }
      if (_pos != 0 || _rpos != 0) {
        throw StateError('Invalid input size');
      }
      if (p > 0) {
        p -= _padding.getPadLength(output, p);
      }
    }

    if (n == p) {
      return output;
    } else if (p == 0) {
      return Uint8List(0);
    } else {
      return output.sublist(0, p);
    }
  }

  @override
  @pragma('vm:prefer-inline')
  Uint8List close() => add([], true);
}

/// Provides encryption for AES cipher in IGE mode.
class AESInIGEModeEncrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#encrypt/IGE/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  @override
  final Uint8List iv;

  /// Padding scheme for the input message
  final Padding padding;

  const AESInIGEModeEncrypt(
    this.key,
    this.iv, [
    this.padding = Padding.pkcs7,
  ]);

  @override
  @pragma('vm:prefer-inline')
  AESInIGEModeEncryptSink createSink() =>
      AESInIGEModeEncryptSink(key, iv, padding);
}

/// Provides decryption for AES cipher in IGE mode.
class AESInIGEModeDecrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#decrypt/IGE/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  @override
  final Uint8List iv;

  /// Padding scheme for the output message
  final Padding padding;

  const AESInIGEModeDecrypt(
    this.key,
    this.iv, [
    this.padding = Padding.pkcs7,
  ]);

  @override
  @pragma('vm:prefer-inline')
  AESInIGEModeDecryptSink createSink() =>
      AESInIGEModeDecryptSink(key, iv, padding);
}

/// Provides encryption and decryption for AES cipher in IGE mode.
class AESInIGEMode extends CollateCipher with SaltedCipher {
  @override
  String get name => "AES/IGE/${padding.name}";

  @override
  final AESInIGEModeEncrypt encryptor;

  @override
  final AESInIGEModeDecrypt decryptor;

  const AESInIGEMode._({
    required this.encryptor,
    required this.decryptor,
  });

  @override
  Uint8List get iv => encryptor.iv;

  /// Creates AES cipher in IGE mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit random initialization vector or salt
  /// - [padding] The padding scheme for the messages
  factory AESInIGEMode(
    List<int> key, {
    List<int>? iv,
    Padding padding = Padding.pkcs7,
  }) {
    iv ??= randomBytes(32);
    if (iv.length < 16) {
      throw StateError('IV must be at least 16-bytes');
    }
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    return AESInIGEMode._(
      encryptor: AESInIGEModeEncrypt(key8, iv8, padding),
      decryptor: AESInIGEModeDecrypt(key8, iv8, padding),
    );
  }

  /// Padding scheme for the messages
  Padding get padding => encryptor.padding;
}
