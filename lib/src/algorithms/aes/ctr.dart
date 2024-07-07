// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/src/algorithms/aes/_core.dart';
import 'package:hashlib/hashlib.dart';

/// The sink used for both encryption and decryption by the
/// [AESInCTRModeCipher] algorithm.
class AESInCTRModeSink extends CipherSink {
  AESInCTRModeSink(this._key, Uint8List iv) {
    if (iv.length != 16) {
      throw StateError('IV must be 16 bytes');
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
        for (j = 15; j >= 8; j--) {
          _iv[j]++;
          if (_iv[j] != 0) break;
        }
      }
      output[i] = _block[_pos] ^ data[i];
      if (++_pos == 16) {
        _pos = 0;
      }
    }

    return output;
  }
}

/// Provides AES cipher in CTR mode.
class AESInCTRModeCipher extends SaltedCipher {
  @override
  final String name = "AES/CTR";

  /// Key for the cipher
  final Uint8List key;

  const AESInCTRModeCipher(this.key, Uint8List iv) : super(iv);

  @override
  @pragma('vm:prefer-inline')
  AESInCTRModeSink createSink() => AESInCTRModeSink(key, iv);
}

/// Provides encryption and decryption for AES cipher in CTR mode.
class AESInCTRMode extends CollateCipher {
  @override
  String get name => "AES/CTR/NoPadding";

  @override
  final AESInCTRModeCipher encryptor;

  @override
  final AESInCTRModeCipher decryptor;

  const AESInCTRMode._({
    required this.encryptor,
    required this.decryptor,
  });

  /// Creates a AES cipher in CTR mode.
  ///
  /// The [iv] parameter combines the 64-bit nonce, and 64-bit counter
  /// value together to make a 128-bit initialization vector for the algorithm.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 128-bit random initialization vector or salt
  factory AESInCTRMode(List<int> key, [List<int>? iv]) {
    iv ??= randomBytes(16);
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    return AESInCTRMode._(
      encryptor: AESInCTRModeCipher(key8, iv8),
      decryptor: AESInCTRModeCipher(key8, iv8),
    );
  }

  /// Creates a AES cipher in CTR mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [nonce] 64-bit random integer nonce
  /// - [counter] 64-bit random integer counter
  factory AESInCTRMode.nonce(
    List<int> key, {
    Salt64? nonce,
    Salt64? counter,
  }) {
    var nonce8 = (nonce ?? Salt64.random()).bytes;
    var counter8 = (counter ?? Salt64.random()).bytes;
    var iv = Uint8List.fromList([...nonce8, ...counter8]);
    return AESInCTRMode(key, iv);
  }

  /// IV for the cipher
  Uint8List get iv => encryptor.iv;

  /// Replaces current IV with a new random one
  @pragma('vm:prefer-inline')
  void resetIV() => fillRandom(iv.buffer);
}
