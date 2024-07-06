// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aes/_core.dart';
import 'package:cipherlib/src/algorithms/padding.dart';
import 'package:cipherlib/src/core/cipher.dart';
import 'package:hashlib/hashlib.dart';

/// The sink used for encryption by the [AESInCBCModeEncrypt] algorithm.
class AESInCBCModeEncryptSink extends CipherSink {
  AESInCBCModeEncryptSink(
    this._key,
    Uint8List _salt,
    this._padding,
  ) {
    if (_salt.lengthInBytes != 16) {
      throw ArgumentError('Salt must be 16-bytes');
    }
    for (int i = 0; i < 16; ++i) {
      _iv[i] = _salt[i];
    }
  }

  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;
  final Padding _padding;
  late final Uint32List _key32 = Uint32List.view(_key.buffer);
  final _iv = Uint8List(16);
  final _block = Uint8List(16); // 128-bit
  late final _block32 = Uint32List.view(_block.buffer);
  late final _xkey32 = AESCore.$expandEncryptionKey(_key32);

  @override
  Uint8List add(List<int> data, [bool last = false]) {
    if (_closed) {
      throw StateError('The sink is closed');
    }
    _closed = last;

    int i, j, p, n;
    p = 0;
    n = _pos + data.length;
    if (last) {
      n += 16 - (n & 15);
    }

    var output = Uint8List(n);
    for (i = 0; i < data.length; ++i) {
      _block[_pos] = data[i] ^ _iv[_pos];
      _pos++;
      if (_pos == 16) {
        AESCore.$encrypt(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          output[p++] = _block[j];
          _iv[j] = _block[j];
        }
        _pos = 0;
      }
    }

    if (last) {
      if (_padding.pad(_block, _pos)) {
        for (; _pos < 16; ++_pos) {
          _block[_pos] ^= _iv[_pos];
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

/// The sink used for decryption by the [AESInCBCModeDecrypt] algorithm.
class AESInCBCModeDecryptSink extends CipherSink {
  AESInCBCModeDecryptSink(
    this._key,
    Uint8List _salt,
    this._padding,
  ) {
    if (_salt.lengthInBytes != 16) {
      throw ArgumentError('Salt must be 16-bytes');
    }
    for (int i = 0; i < 16; ++i) {
      _iv[i] = _salt[i];
    }
  }

  int _pos = 0;
  int _rpos = 0;
  bool _closed = false;
  final Uint8List _key;
  final Padding _padding;
  late final Uint32List _key32 = Uint32List.view(_key.buffer);
  final _block = Uint8List(16); // 128-bit
  final _iv = Uint8List(16);
  final _nextIV = Uint8List(16);
  final _residue = Uint8List(16);
  late final _block32 = Uint32List.view(_block.buffer);
  late final _xkey32 = AESCore.$expandDecryptionKey(_key32);

  @override
  Uint8List add(List<int> data, [bool last = false]) {
    if (_closed) {
      throw StateError('The sink is closed');
    }
    _closed = last;

    int i, j, k, p, n;
    p = 0;
    n = _rpos + data.length;

    var output = Uint8List(n);
    for (i = 0; i < data.length; ++i) {
      _nextIV[_pos] = _block[_pos] = data[i];
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
          _residue[_rpos++] = _block[j] ^ _iv[j];
          _iv[j] = _nextIV[j];
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
    Uint8List salt, [
    this.padding = Padding.pkcs7,
  ]) : super(salt);

  @override
  @pragma('vm:prefer-inline')
  AESInCBCModeEncryptSink createSink() =>
      AESInCBCModeEncryptSink(key, salt, padding);
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
    Uint8List salt, [
    this.padding = Padding.pkcs7,
  ]) : super(salt);

  @override
  @pragma('vm:prefer-inline')
  AESInCBCModeDecryptSink createSink() =>
      AESInCBCModeDecryptSink(key, salt, padding);
}

/// Provides encryption and decryption for AES cipher in CBC mode.
class AESInCBCMode extends CollateCipher {
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

  factory AESInCBCMode(
    List<int> key,
    List<int>? salt, [
    Padding padding = Padding.pkcs7,
  ]) {
    salt ??= randomBytes(16);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    var salt8 = salt is Uint8List ? salt : Uint8List.fromList(salt);
    return AESInCBCMode._(
      encryptor: AESInCBCModeEncrypt(key8, salt8, padding),
      decryptor: AESInCBCModeDecrypt(key8, salt8, padding),
    );
  }

  /// Padding scheme for the messages
  Padding get padding => encryptor.padding;

  /// Salt for the cipher
  Uint8List get salt => encryptor.salt;

  /// Replaces the current IV or salt with random bytes
  @pragma('vm:prefer-inline')
  void resetIV() => fillRandom(salt.buffer);
}
