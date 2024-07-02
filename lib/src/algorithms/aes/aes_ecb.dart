// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aes/aes_core.dart';
import 'package:cipherlib/src/core/cipher.dart';

/// The sink used for encryption by the [AESEncryptInECBMode] algorithm.
class AESEncryptSinkInECBMode extends CipherSink {
  AESEncryptSinkInECBMode(this._key);

  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;
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
    n = _pos + data.length;
    var output = Uint8List(n);
    for (i = p = 0; i < data.length; ++i) {
      _block[_pos++] = data[i];
      if (_pos == 16) {
        AESCore.$encrypt(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          output[p++] = _block[j];
        }
        _pos = 0;
      }
    }

    if (_pos == 0) {
      return output;
    }
    if (last) {
      throw StateError('Invalid input size');
    }
    return output.sublist(0, n - _pos);
  }
}

/// The sink used for decryption by the [AESDecryptInECBMode] algorithm.
class AESDecryptSinkInECBMode extends CipherSink {
  AESDecryptSinkInECBMode(this._key);

  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;
  late final Uint32List _key32 = Uint32List.view(_key.buffer);
  final _block = Uint8List(16); // 128-bit
  late final _block32 = Uint32List.view(_block.buffer);
  late final _xkey32 = AESCore.$expandDecryptionKey(_key32);

  @override
  Uint8List add(List<int> data, [bool last = false]) {
    if (_closed) {
      throw StateError('The sink is closed');
    }
    _closed = last;

    int i, j, p, n;
    n = _pos + data.length;
    var output = Uint8List(n);
    for (i = p = 0; i < data.length; ++i) {
      _block[_pos++] = data[i];
      if (_pos == 16) {
        AESCore.$decrypt(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          output[p++] = _block[j];
        }
        _pos = 0;
      }
    }

    if (_pos == 0) {
      return output;
    }
    if (last) {
      throw StateError('Invalid input size');
    }
    return output.sublist(0, n - _pos);
  }
}

/// Provides encryption for AES cipher in ECB mode.
class AESEncryptInECBMode extends Cipher {
  @override
  final String name = "AES/ECB#Encrypt";

  /// Key for the cipher
  final Uint8List key;

  const AESEncryptInECBMode(this.key);

  /// Creates a [AESEncryptInECBMode] with List<int> [key].
  ///
  /// Every elements of the both list is transformed to unsigned 8-bit numbers.
  factory AESEncryptInECBMode.fromList(List<int> key) => AESEncryptInECBMode(
        key = key is Uint8List ? key : Uint8List.fromList(key),
      );

  @override
  @pragma('vm:prefer-inline')
  CipherSink createSink() => AESEncryptSinkInECBMode(key);
}

/// Provides decryption for AES cipher in ECB mode.
class AESDecryptInECBMode extends Cipher {
  @override
  final String name = "AES/ECB#Decrypt";

  /// Key for the cipher
  final Uint8List key;

  const AESDecryptInECBMode(this.key);

  /// Creates a [AESDecryptInECBMode] with List<int> [key].
  ///
  /// Every elements of the both list is transformed to unsigned 8-bit numbers.
  factory AESDecryptInECBMode.fromList(List<int> key) => AESDecryptInECBMode(
        key = key is Uint8List ? key : Uint8List.fromList(key),
      );

  @override
  @pragma('vm:prefer-inline')
  CipherSink createSink() => AESDecryptSinkInECBMode(key);
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

  factory AESInECBMode(List<int> key) {
    return AESInECBMode._(
      encryptor: AESEncryptInECBMode.fromList(key),
      decryptor: AESDecryptInECBMode.fromList(key),
    );
  }
}
