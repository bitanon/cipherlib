// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/padding.dart';
import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:cipherlib/src/core/salted_cipher.dart';
import 'package:hashlib/hashlib.dart' show randomBytes;

import '_core.dart';

/// The sink used for encryption by the [AESInCBCModeEncrypt] algorithm.
class AESInCBCModeEncryptSink extends CipherSink {
  AESInCBCModeEncryptSink(
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
  final _temp = Uint8List(16);
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
      _block[i] = _iv[i];
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

    int i, j, p, n;

    n = _pos + end - start;
    if (last) {
      n += 16 - (n & 15);
    }
    var output = Uint8List(n);

    p = 0;
    for (i = start; i < end; ++i) {
      _block[_pos] ^= data[i];
      _pos++;
      if (_pos == 16) {
        AESCore.$encryptLE(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          output[p++] = _block[j];
        }
        _pos = 0;
      }
    }

    if (last) {
      for (j = _pos; j < 16; ++j) {
        _temp[j] = _block[j];
      }
      if (_padding.pad(_block, _pos)) {
        for (j = _pos; j < 16; ++j) {
          _block[j] ^= _temp[j];
        }
        AESCore.$encryptLE(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          output[p++] = _block[j];
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
}

/// The sink used for decryption by the [AESInCBCModeDecrypt] algorithm.
class AESInCBCModeDecryptSink extends CipherSink {
  AESInCBCModeDecryptSink(
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
  final _salt = Uint8List(16);
  final _nextSalt = Uint8List(16);
  final _residue = Uint8List(16);
  late final _block32 = Uint32List.view(_block.buffer);
  late final _xkey32 = AESCore.$expandDecryptionKey(_key32);

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

    int i, j, k, p, n;

    n = _rpos + end - start;
    var output = Uint8List(n);

    p = 0;
    for (i = start; i < end; ++i) {
      _block[_pos] = data[i];
      _nextSalt[_pos] = _block[_pos];
      _pos++;
      if (_pos == 16) {
        AESCore.$decryptLE(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          if (_rpos == 16) {
            for (k = 0; k < 16; ++k) {
              output[p++] = _residue[k];
            }
            _rpos = 0;
          }
          _residue[_rpos++] = _block[j] ^ _salt[j];
          _salt[j] = _nextSalt[j];
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
}

/// Provides encryption for AES cipher in CBC mode.
class AESInCBCModeEncrypt extends SaltedCipher {
  @override
  String get name => "AES#encrypt/CBC/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Padding scheme for the input message
  final Padding padding;

  const AESInCBCModeEncrypt(
    this.key,
    Uint8List iv, [
    this.padding = Padding.pkcs7,
  ]) : super(iv);

  @override
  @pragma('vm:prefer-inline')
  AESInCBCModeEncryptSink createSink() =>
      AESInCBCModeEncryptSink(key, iv, padding);
}

/// Provides decryption for AES cipher in CBC mode.
class AESInCBCModeDecrypt extends SaltedCipher {
  @override
  String get name => "AES#decrypt/CBC/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Padding scheme for the output message
  final Padding padding;

  const AESInCBCModeDecrypt(
    this.key,
    Uint8List iv, [
    this.padding = Padding.pkcs7,
  ]) : super(iv);

  @override
  @pragma('vm:prefer-inline')
  AESInCBCModeDecryptSink createSink() =>
      AESInCBCModeDecryptSink(key, iv, padding);
}

/// Provides encryption and decryption for AES cipher in CBC mode.
class AESInCBCMode extends SaltedCollateCipher {
  @override
  String get name => "AES/CBC/${padding.name}";

  @override
  final AESInCBCModeEncrypt encryptor;

  @override
  final AESInCBCModeDecrypt decryptor;

  const AESInCBCMode._({
    required this.encryptor,
    required this.decryptor,
  });

  /// Creates AES cipher in CBC mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit random initialization vector or salt
  /// - [padding] The padding scheme for the messages
  factory AESInCBCMode(
    List<int> key, {
    List<int>? iv,
    Padding padding = Padding.pkcs7,
  }) {
    iv ??= randomBytes(16);
    if (iv.length < 16) {
      throw StateError('IV must be at least 16-bytes');
    }
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    return AESInCBCMode._(
      encryptor: AESInCBCModeEncrypt(key8, iv8, padding),
      decryptor: AESInCBCModeDecrypt(key8, iv8, padding),
    );
  }

  /// Padding scheme for the messages
  Padding get padding => encryptor.padding;
}
