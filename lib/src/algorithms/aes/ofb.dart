// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aes/_core.dart';
import 'package:cipherlib/src/core/cipher.dart';
import 'package:hashlib/hashlib.dart';

/// The sink used for encryption by the [AESInOFBModeCipher] algorithm.
class AESInOFBModeSink extends CipherSink {
  AESInOFBModeSink(
    this._key,
    Uint8List iv,
  ) {
    if (iv.lengthInBytes != 16) {
      throw StateError('IV must be 16-bytes');
    }
    for (int i = 0; i < 16; ++i) {
      _iv[i] = iv[i];
    }
  }

  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;
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

    int i, j;
    var output = Uint8List(data.length);
    for (i = 0; i < data.length; ++i) {
      if (_pos == 0) {
        for (j = 0; j < 16; ++j) {
          _block[j] = _iv[j];
        }
        AESCore.$encrypt(_block32, _xkey32);
        for (j = 0; j < 16; ++j) {
          _iv[j] = _block[j];
        }
      }
      output[i] = _block[_pos] ^ data[i];
      _pos = (_pos + 1) & 15;
    }

    return output;
  }
}

/// Provides encryption for AES cipher in OFB mode.
class AESInOFBModeCipher extends SaltedCipher {
  @override
  final String name = "AES#cipher/OFB";

  /// Key for the cipher
  final Uint8List key;

  const AESInOFBModeCipher(this.key, Uint8List iv) : super(iv);

  @override
  @pragma('vm:prefer-inline')
  AESInOFBModeSink createSink() => AESInOFBModeSink(key, iv);
}

/// Provides encryption and decryption for AES cipher in OFB mode.
class AESInOFBMode extends CollateCipher {
  @override
  final String name = "AES/OFB";

  @override
  final AESInOFBModeCipher encryptor;

  @override
  final AESInOFBModeCipher decryptor;

  const AESInOFBMode._({
    required this.encryptor,
    required this.decryptor,
  });

  /// Creates a AES cipher in OFB mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit random initialization vector or salt
  factory AESInOFBMode(List<int> key, [List<int>? iv]) {
    iv ??= randomBytes(16);
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    var cipher = AESInOFBModeCipher(key8, iv8);
    return AESInOFBMode._(
      encryptor: cipher,
      decryptor: cipher,
    );
  }

  /// IV for the cipher
  Uint8List get iv => encryptor.iv;

  /// Replaces current IV with a new random one
  @pragma('vm:prefer-inline')
  void resetIV() => fillRandom(iv.buffer);
}
