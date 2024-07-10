// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/padding.dart';
import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:cipherlib/src/core/salted_cipher.dart';
import 'package:hashlib/hashlib.dart';

import '_core.dart';

/// The sink used for encryption by the [AESInPCBCModeEncrypt] algorithm.
class AESInPCBCModeEncryptSink extends CipherSink {
  AESInPCBCModeEncryptSink(
    this._key,
    this._iv,
    this._padding,
  ) {
    reset();
  }

  int _pos = 0;
  bool _closed = false;
  int _messageLength = 0;
  final Uint8List _key;
  final Uint8List _iv;
  final Padding _padding;
  late final Uint32List _key32 = Uint32List.view(_key.buffer);
  final _salt = Uint8List(16);
  final _block = Uint8List(16); // 128-bit
  final _history = Uint8List(16);
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
    _messageLength += end - start;
    if (last && _messageLength == 0) {
      return Uint8List(0);
    }

    int i, j, p, n;
    p = 0;
    n = _pos + end - start;
    if (last) {
      n += 16 - (n & 15);
    }
    var output = Uint8List(n);
    for (i = start; i < end; ++i) {
      _block[_pos] = data[i] ^ _salt[_pos];
      _history[_pos] = data[i];
      _pos++;
      if (_pos == 16) {
        AESCore.$encrypt(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          output[p++] = _block[j];
          _salt[j] = _block[j] ^ _history[j];
        }
        _pos = 0;
      }
    }

    if (last) {
      if (_padding.pad(_block, _pos)) {
        for (; _pos < 16; ++_pos) {
          _block[_pos] ^= _salt[_pos];
        }
        AESCore.$encrypt(_block32, _xkey32);
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

/// The sink used for decryption by the [AESInPCBCModeDecrypt] algorithm.
class AESInPCBCModeDecryptSink extends CipherSink {
  AESInPCBCModeDecryptSink(
    this._key,
    this._iv,
    this._padding,
  ) {
    reset();
  }

  int _pos = 0;
  int _rpos = 0;
  bool _closed = false;
  int _messageLength = 0;
  final Uint8List _key;
  final Uint8List _iv;
  final Padding _padding;
  late final Uint32List _key32 = Uint32List.view(_key.buffer);
  final _block = Uint8List(16); // 128-bit
  final _salt = Uint8List(16);
  final _nextIV = Uint8List(16);
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
    _messageLength += end - start;
    if (last && _messageLength == 0) {
      return Uint8List(0);
    }

    int i, j, k, p, n;
    p = 0;
    n = _rpos + end - start;
    var output = Uint8List(n);
    for (i = start; i < end; ++i) {
      _block[_pos] = data[i];
      _nextIV[_pos] = data[i];
      _pos++;
      if (_pos == 16) {
        AESCore.$decrypt(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          if (_rpos == 16) {
            for (k = 0; k < 16; ++k) {
              output[p++] = _residue[k];
            }
            _rpos = 0;
          }
          _residue[_rpos] = _block[j] ^ _salt[j];
          _salt[j] = _nextIV[j] ^ _residue[_rpos];
          _rpos++;
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
      p -= _padding.getPadLength(output);
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

/// Provides encryption for AES cipher in PCBC mode.
class AESInPCBCModeEncrypt extends SaltedCipher {
  @override
  String get name => "AES#encrypt/PCBC/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Padding scheme for the input message
  final Padding padding;

  const AESInPCBCModeEncrypt(
    this.key,
    Uint8List iv, [
    this.padding = Padding.pkcs7,
  ]) : super(iv);

  @override
  @pragma('vm:prefer-inline')
  AESInPCBCModeEncryptSink createSink() =>
      AESInPCBCModeEncryptSink(key, iv, padding);
}

/// Provides decryption for AES cipher in PCBC mode.
class AESInPCBCModeDecrypt extends SaltedCipher {
  @override
  String get name => "AES#decrypt/PCBC/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Padding scheme for the output message
  final Padding padding;

  const AESInPCBCModeDecrypt(
    this.key,
    Uint8List iv, [
    this.padding = Padding.pkcs7,
  ]) : super(iv);

  @override
  @pragma('vm:prefer-inline')
  AESInPCBCModeDecryptSink createSink() =>
      AESInPCBCModeDecryptSink(key, iv, padding);
}

/// Provides encryption and decryption for AES cipher in PCBC mode.
class AESInPCBCMode extends SaltedCollateCipher {
  @override
  String get name => "AES/PCBC/${padding.name}";

  @override
  final AESInPCBCModeEncrypt encryptor;

  @override
  final AESInPCBCModeDecrypt decryptor;

  const AESInPCBCMode._({
    required this.encryptor,
    required this.decryptor,
  });

  /// Creates AES cipher in PCBC mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit random initialization vector or salt
  /// - [padding] The padding scheme for the messages
  factory AESInPCBCMode(
    List<int> key, {
    List<int>? iv,
    Padding padding = Padding.pkcs7,
  }) {
    iv ??= randomBytes(16);
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    if (iv8.lengthInBytes < 16) {
      throw StateError('IV must be at least 16-bytes');
    }
    return AESInPCBCMode._(
      encryptor: AESInPCBCModeEncrypt(key8, iv8, padding),
      decryptor: AESInPCBCModeDecrypt(key8, iv8, padding),
    );
  }

  /// Padding scheme for the messages
  Padding get padding => encryptor.padding;
}
