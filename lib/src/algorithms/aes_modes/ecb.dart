// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import '../../core/cipher.dart';
import '../../core/cipher_sink.dart';
import '../../core/collate_cipher.dart';
import '../aes.dart';
import '../padding.dart';

/// The sink used for encryption by the [AESInECBModeEncrypt] algorithm.
class AESInECBModeEncryptSink extends CipherSink {
  AESInECBModeEncryptSink(
    this._key,
    this._padding,
  ) {
    reset();
  }

  int _pos = 0;
  final Uint8List _key;
  final Padding _padding;
  final _block = Uint8List(16); // 128-bit
  late final _key32 = Uint32List.view(_key.buffer);
  late final _block32 = Uint32List.view(_block.buffer);
  late final _xkey32 = AESCore.$expandEncryptionKey(_key32);

  @override
  void reset() {
    super.reset();
    _pos = 0;
  }

  @override
  @pragma('vm:prefer-inline')
  Uint8List $add(List<int> data, int start, int end) {
    int i, j, p, n;
    n = _pos + end - start;
    if (closed) {
      n += 16 - (n & 15);
    }
    var output = Uint8List(n);

    p = 0;
    for (i = start; i < end;) {
      for (; _pos < 16 && i < end; ++_pos, ++i) {
        _block[_pos] = data[i];
      }
      if (_pos == 16) {
        AESCore.$encryptLE(_block32, _xkey32);
        for (j = 0; j < 16; ++j, ++p) {
          output[p] = _block[j];
        }
        _pos = 0;
      }
    }

    if (closed) {
      if (_padding.pad(_block, _pos)) {
        AESCore.$encryptLE(_block32, _xkey32);
        for (j = 0; j < 16; ++j, ++p) {
          output[p] = _block[j];
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

/// The sink used for decryption by the [AESInECBModeDecrypt] algorithm.
class AESInECBModeDecryptSink extends CipherSink {
  AESInECBModeDecryptSink(
    this._key,
    this._padding,
  ) {
    reset();
  }

  int _pos = 0;
  int _rpos = 0;
  final Uint8List _key;
  final Padding _padding;
  final _block = Uint8List(16); // 128-bit
  final _residue = Uint8List(16);
  late final _key32 = Uint32List.view(_key.buffer);
  late final _block32 = Uint32List.view(_block.buffer);
  late final _xkey32 = AESCore.$expandDecryptionKey(_key32);

  @override
  void reset() {
    super.reset();
    _pos = 0;
    _rpos = 0;
  }

  @override
  @pragma('vm:prefer-inline')
  Uint8List $add(List<int> data, int start, int end) {
    int i, j, k, p, n;
    p = 0;
    n = _rpos + end - start;
    var output = Uint8List(n);
    for (i = start; i < end;) {
      for (; _pos < 16 && i < end; ++_pos, ++i) {
        _block[_pos] = data[i];
      }
      if (_pos == 16) {
        AESCore.$decryptLE(_block32, _xkey32);
        for (j = 0; j < 16; ++j, ++_rpos) {
          if (_rpos == 16) {
            for (k = 0; k < 16; ++k, ++p) {
              output[p] = _residue[k];
            }
            _rpos = 0;
          }
          _residue[_rpos] = _block[j];
        }
        _pos = 0;
      }
    }

    if (closed) {
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

/// Provides encryption for AES cipher in ECB mode.
class AESInECBModeEncrypt extends Cipher {
  @override
  String get name => "AES#encrypt/ECB/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Padding scheme for the input message
  final Padding padding;

  const AESInECBModeEncrypt(
    this.key, [
    this.padding = Padding.pkcs7,
  ]);

  @override
  @pragma('vm:prefer-inline')
  AESInECBModeEncryptSink createSink() => AESInECBModeEncryptSink(key, padding);
}

/// Provides decryption for AES cipher in ECB mode.
class AESInECBModeDecrypt extends Cipher {
  @override
  String get name => "AES#decrypt/ECB/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Padding scheme for the output message
  final Padding padding;

  const AESInECBModeDecrypt(
    this.key, [
    this.padding = Padding.pkcs7,
  ]);

  @override
  @pragma('vm:prefer-inline')
  AESInECBModeDecryptSink createSink() => AESInECBModeDecryptSink(key, padding);
}

/// Provides encryption and decryption for AES cipher in ECB mode.
class AESInECBMode extends CollateCipher {
  @override
  String get name => "AES/ECB/${padding.name}";

  @override
  final AESInECBModeEncrypt encryptor;

  @override
  final AESInECBModeDecrypt decryptor;

  const AESInECBMode._({
    required this.encryptor,
    required this.decryptor,
  });

  /// Creates AES cipher in ECB mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [padding] The padding scheme for the messages
  factory AESInECBMode(
    List<int> key, [
    Padding padding = Padding.pkcs7,
  ]) {
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    return AESInECBMode._(
      encryptor: AESInECBModeEncrypt(key8, padding),
      decryptor: AESInECBModeDecrypt(key8, padding),
    );
  }

  /// Padding scheme for the messages
  Padding get padding => encryptor.padding;
}
