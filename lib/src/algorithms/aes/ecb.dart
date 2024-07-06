// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aes/_core.dart';
import 'package:cipherlib/src/algorithms/padding.dart';
import 'package:cipherlib/src/core/cipher.dart';

/// The sink used for encryption by the [AESEncryptInECBMode] algorithm.
class AESEncryptSinkInECBMode extends CipherSink {
  AESEncryptSinkInECBMode(
    this._key,
    this._padding,
  );

  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;
  final Padding _padding;
  late final Uint32List _key32 = Uint32List.view(_key.buffer);
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
      _block[_pos++] = data[i];
      if (_pos == 16) {
        AESCore.$encrypt(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          output[p++] = _block[j];
        }
        _pos = 0;
      }
    }

    if (last) {
      if (_padding.pad(_block, _pos)) {
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

/// The sink used for decryption by the [AESDecryptInECBMode] algorithm.
class AESDecryptSinkInECBMode extends CipherSink {
  AESDecryptSinkInECBMode(
    this._key,
    this._padding,
  );

  int _pos = 0;
  int _rpos = 0;
  bool _closed = false;
  final Uint8List _key;
  final Padding _padding;
  late final Uint32List _key32 = Uint32List.view(_key.buffer);
  final _block = Uint8List(16); // 128-bit
  final _residue = Uint8List(16); // 128-bit
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
      _block[_pos++] = data[i];
      if (_pos == 16) {
        AESCore.$decrypt(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          if (_rpos == 16) {
            for (k = 0; k < 16; ++k) {
              output[p++] = _residue[k];
            }
            _rpos = 0;
          }
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

/// Provides encryption for AES cipher in ECB mode.
class AESEncryptInECBMode extends Cipher {
  @override
  final String name = "AES/ECB#Encrypt";

  /// Key for the cipher
  final Uint8List key;

  /// Padding scheme for the input message
  final Padding padding;

  const AESEncryptInECBMode(this.key, [this.padding = Padding.pkcs7]);

  /// Creates a [AESEncryptInECBMode] with List<int> [key].
  ///
  /// Every elements of the both list is transformed to unsigned 8-bit numbers.
  factory AESEncryptInECBMode.fromList(
    List<int> key, [
    Padding padding = Padding.pkcs7,
  ]) =>
      AESEncryptInECBMode(
        key = key is Uint8List ? key : Uint8List.fromList(key),
        padding,
      );

  @override
  @pragma('vm:prefer-inline')
  CipherSink createSink() => AESEncryptSinkInECBMode(key, padding);
}

/// Provides decryption for AES cipher in ECB mode.
class AESDecryptInECBMode extends Cipher {
  @override
  final String name = "AES/ECB#Decrypt";

  /// Key for the cipher
  final Uint8List key;

  /// Padding scheme for the output message
  final Padding padding;

  const AESDecryptInECBMode(this.key, [this.padding = Padding.pkcs7]);

  /// Creates a [AESDecryptInECBMode] with List<int> [key].
  ///
  /// Every elements of the both list is transformed to unsigned 8-bit numbers.
  factory AESDecryptInECBMode.fromList(
    List<int> key, [
    Padding padding = Padding.pkcs7,
  ]) =>
      AESDecryptInECBMode(
        key = key is Uint8List ? key : Uint8List.fromList(key),
        padding,
      );

  @override
  @pragma('vm:prefer-inline')
  CipherSink createSink() => AESDecryptSinkInECBMode(key, padding);
}

/// Provides encryption and decryption for AES cipher in ECB mode.
class AESInECBMode extends CollateCipher {
  @override
  String get name => "AES/ECB";

  @override
  final AESEncryptInECBMode encryptor;

  @override
  final AESDecryptInECBMode decryptor;

  const AESInECBMode._({
    required this.encryptor,
    required this.decryptor,
  });

  factory AESInECBMode(
    List<int> key, [
    Padding padding = Padding.pkcs7,
  ]) {
    return AESInECBMode._(
      encryptor: AESEncryptInECBMode.fromList(key, padding),
      decryptor: AESDecryptInECBMode.fromList(key, padding),
    );
  }

  /// Padding scheme for the messages
  Padding get padding => encryptor.padding;
}
