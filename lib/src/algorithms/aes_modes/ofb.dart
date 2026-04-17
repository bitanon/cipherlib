// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../../core/cipher.dart';
import '../../core/cipher_sink.dart';
import '../../core/collate_cipher.dart';
import '../aes.dart';
import '../padding.dart';

/// The sink used for encryption by the [AESInOFBModeCipher] algorithm.
class AESInOFBModeSink extends CipherSink {
  AESInOFBModeSink(
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
    _nextBlock();
  }

  @pragma('vm:prefer-inline')
  void _nextBlock() {
    int i;
    for (i = 0; i < 16; ++i) {
      _block[i] = _salt[i];
    }
    AESCore.$encryptLE(_block32, _xkey32);
    for (i = _sbyte; i < 16; ++i) {
      _salt[i - _sbyte] = _salt[i];
    }
    for (i = 0; i < _sbyte; ++i) {
      _salt[16 - _sbyte + i] = _block[i];
    }
  }

  @override
  @pragma('vm:prefer-inline')
  Uint8List $add(List<int> data, int start, int end) {
    int i, p;
    var output = Uint8List(end - start);

    p = 0;
    for (i = start; i < end;) {
      for (; _pos < _sbyte && i < end; ++_pos, ++i, ++p) {
        output[p] = _block[_pos] ^ data[i];
      }
      if (_pos == _sbyte) {
        _nextBlock();
        _pos = 0;
      }
    }

    return output;
  }
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
