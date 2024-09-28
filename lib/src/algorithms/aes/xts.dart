// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';
import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:cipherlib/src/core/collate_cipher.dart';
import 'package:cipherlib/src/utils/nonce.dart';
import 'package:hashlib/random.dart' show randomBytes;

import '../padding.dart';
import '_core.dart';

/// Multiply [T] by `alpha` = `0x87` in 128-bit Galois Field
void _multiplyAlpha(Uint8List T) {
  int c = 0;
  for (int i = 0; i < 16; i++) {
    c ^= T[i] << 1;
    T[i] = c;
    c >>>= 8;
  }
  if (c == 1) {
    T[0] ^= 0x87;
  }
}

/// This implementation is derived from [1619-2018 - IEEE Standard for
/// Cryptographic Protection of Data on Block-Oriented Storage Devices][spec].
///
/// [spec]: https://ieeexplore.ieee.org/document/8637988
class AESInXTSModeEncryptSink implements CipherSink {
  AESInXTSModeEncryptSink(
    this._ekey,
    this._tkey,
    this._iv,
  ) {
    reset();
  }

  int _pos = 0;
  int _rpos = 0;
  bool _closed = false;
  bool _firstBlockAvailable = false;
  final Uint8List _ekey;
  final Uint8List _tkey;
  final Uint8List _iv;
  final _residue = Uint8List(16);
  final _tweak = Uint8List(16);
  final _block = Uint8List(16); // 128-bit
  late final _ekey32 = Uint32List.view(_ekey.buffer);
  late final _tkey32 = Uint32List.view(_tkey.buffer);
  late final _block32 = Uint32List.view(_block.buffer);
  late final _tweak32 = Uint32List.view(_tweak.buffer);
  late final _xekey32 = AESCore.$expandEncryptionKey(_ekey32);
  late final _xtkey32 = AESCore.$expandEncryptionKey(_tkey32);

  @override
  bool get closed => _closed;

  @override
  void reset() {
    _pos = 0;
    _rpos = 0;
    _closed = false;
    _firstBlockAvailable = false;
    for (int i = 0; i < 16; ++i) {
      _tweak[i] = _iv[i];
    }
    AESCore.$encryptLE(_tweak32, _xtkey32);
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
    if (!last) n -= 16;
    n += _firstBlockAvailable ? 16 : _rpos;
    if (!last) n -= (n & 15);
    if (n < 0) n = 0;
    var output = Uint8List(n);

    p = 0;
    for (i = start; i < end; ++i) {
      if (_firstBlockAvailable) {
        _block[_pos] = _residue[_rpos];
        _pos++;
        if (_pos == 16) {
          for (j = 0; j < 16; j++) {
            _block[j] ^= _tweak[j];
          }
          AESCore.$encryptLE(_block32, _xekey32);
          for (j = 0; j < 16; ++j) {
            output[p++] = _block[j] ^ _tweak[j];
          }
          _multiplyAlpha(_tweak);
          _pos = 0;
        }
      }
      _residue[_rpos++] = data[i];
      if (_rpos == 16) {
        _firstBlockAvailable = true;
        _rpos = 0;
      }
    }

    if (last) {
      if (!_firstBlockAvailable) {
        throw StateError('The message length must be at least 16-bytes');
      }
      n = _pos;
      for (j = n; j < 16; j++) {
        _block[j] = _residue[j];
      }
      if (n == 0) {
        // on full block
        for (j = 0; j < 16; j++) {
          _block[j] ^= _tweak[j];
        }
        AESCore.$encryptLE(_block32, _xekey32);
        for (j = 0; j < 16; ++j) {
          output[p++] = _block[j] ^ _tweak[j];
        }
      } else {
        // on partial block
        for (j = 0; j < 16; j++) {
          _block[j] ^= _tweak[j];
        }
        AESCore.$encryptLE(_block32, _xekey32);
        for (j = 0; j < 16; j++) {
          _block[j] ^= _tweak[j];
        }
        for (j = 0; j < n; j++) {
          i = _block[j];
          _block[j] = _residue[j];
          _residue[j] = i;
        }
        _multiplyAlpha(_tweak);
        for (j = 0; j < 16; j++) {
          _block[j] ^= _tweak[j];
        }
        AESCore.$encryptLE(_block32, _xekey32);
        for (j = 0; j < 16; j++) {
          _block[j] ^= _tweak[j];
        }
        for (j = 0; j < 16; ++j) {
          output[p++] = _block[j];
        }
        for (j = 0; j < n; ++j) {
          output[p++] = _residue[j];
        }
      }
    }

    if (n == p) {
      return output;
    } else {
      return output.sublist(0, p);
    }
  }

  @override
  @pragma('vm:prefer-inline')
  Uint8List close() => add([], true);
}

/// This implementation is derived from [1619-2018 - IEEE Standard for
/// Cryptographic Protection of Data on Block-Oriented Storage Devices][spec].
///
/// [spec]: https://ieeexplore.ieee.org/document/8637988
class AESInXTSModeDecryptSink implements CipherSink {
  AESInXTSModeDecryptSink(
    this._dkey,
    this._tkey,
    this._iv,
  ) {
    reset();
  }

  int _pos = 0;
  int _rpos = 0;
  bool _closed = false;
  bool _firstBlockAvailable = false;
  final Uint8List _dkey;
  final Uint8List _tkey;
  final Uint8List _iv;
  final _residue = Uint8List(16);
  final _tweak = Uint8List(16);
  final _temp = Uint8List(16);
  final _block = Uint8List(16); // 128-bit
  late final _dkey32 = Uint32List.view(_dkey.buffer);
  late final _tkey32 = Uint32List.view(_tkey.buffer);
  late final _block32 = Uint32List.view(_block.buffer);
  late final _tweak32 = Uint32List.view(_tweak.buffer);
  late final _xdkey32 = AESCore.$expandDecryptionKey(_dkey32);
  late final _xtkey32 = AESCore.$expandEncryptionKey(_tkey32);

  @override
  bool get closed => _closed;

  @override
  void reset() {
    _pos = 0;
    _rpos = 0;
    _closed = false;
    _firstBlockAvailable = false;
    for (int i = 0; i < 16; ++i) {
      _tweak[i] = _iv[i];
    }
    AESCore.$encryptLE(_tweak32, _xtkey32);
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
    if (!last) n -= 16;
    n += _firstBlockAvailable ? 16 : _rpos;
    if (!last) n -= (n & 15);
    if (n < 0) n = 0;
    var output = Uint8List(n);

    p = 0;
    for (i = start; i < end; ++i) {
      if (_firstBlockAvailable) {
        _block[_pos] = _residue[_rpos];
        _pos++;
        if (_pos == 16) {
          for (j = 0; j < 16; j++) {
            _block[j] ^= _tweak[j];
          }
          AESCore.$decryptLE(_block32, _xdkey32);
          for (j = 0; j < 16; ++j) {
            output[p++] = _block[j] ^ _tweak[j];
          }
          _multiplyAlpha(_tweak);
          _pos = 0;
        }
      }
      _residue[_rpos++] = data[i];
      if (_rpos == 16) {
        _firstBlockAvailable = true;
        _rpos = 0;
      }
    }

    if (last) {
      if (!_firstBlockAvailable) {
        throw StateError('The message length must be at least 16-bytes');
      }
      n = _pos;
      for (j = n; j < 16; j++) {
        _block[j] = _residue[j];
      }
      if (n == 0) {
        // on full block
        for (j = 0; j < 16; j++) {
          _block[j] ^= _tweak[j];
        }
        AESCore.$decryptLE(_block32, _xdkey32);
        for (j = 0; j < 16; ++j) {
          output[p++] = _block[j] ^ _tweak[j];
        }
      } else {
        // on partial block
        for (j = 0; j < 16; j++) {
          _temp[j] ^= _tweak[j];
        }
        _multiplyAlpha(_tweak);
        for (j = 0; j < 16; j++) {
          _block[j] ^= _tweak[j];
        }
        AESCore.$decryptLE(_block32, _xdkey32);
        for (j = 0; j < 16; j++) {
          _block[j] ^= _tweak[j];
        }
        for (j = 0; j < n; j++) {
          i = _block[j];
          _block[j] = _residue[j];
          _residue[j] = i;
        }
        for (j = 0; j < 16; j++) {
          _block[j] ^= _temp[j];
        }
        AESCore.$decryptLE(_block32, _xdkey32);
        for (j = 0; j < 16; ++j) {
          output[p++] = _block[j] ^ _temp[j];
        }
        for (j = 0; j < n; ++j) {
          output[p++] = _residue[j];
        }
      }
    }

    if (n == p) {
      return output;
    } else {
      return output.sublist(0, p);
    }
  }

  @override
  @pragma('vm:prefer-inline')
  Uint8List close() => add([], true);
}

/// Provides encryption for AES cipher in XTS mode.
class AESInXTSModeEncrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#encrypt/XTS/${Padding.none.name}";

  /// Key for the plaintext encryption
  final Uint8List ekey;

  /// Key for the tweak encryption
  final Uint8List tkey;

  @override
  final Uint8List iv;

  const AESInXTSModeEncrypt(
    this.ekey,
    this.tkey,
    this.iv,
  );

  @override
  @pragma('vm:prefer-inline')
  AESInXTSModeEncryptSink createSink() =>
      AESInXTSModeEncryptSink(ekey, tkey, iv);
}

/// Provides decryption for AES cipher in XTS mode.
class AESInXTSModeDecrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#decrypt/XTS/${Padding.none.name}";

  /// Key for the ciphertext decryption
  final Uint8List ekey;

  /// Key for the tweak encryption
  final Uint8List tkey;

  @override
  final Uint8List iv;

  const AESInXTSModeDecrypt(
    this.ekey,
    this.tkey,
    this.iv,
  );

  @override
  @pragma('vm:prefer-inline')
  AESInXTSModeDecryptSink createSink() =>
      AESInXTSModeDecryptSink(ekey, tkey, iv);
}

/// Provides encryption and decryption for AES cipher in XTS mode.
class AESInXTSMode extends CollateCipher with SaltedCipher {
  @override
  String get name => "AES/XTS/${Padding.none.name}";

  @override
  final AESInXTSModeEncrypt encryptor;

  @override
  final AESInXTSModeDecrypt decryptor;

  const AESInXTSMode._({
    required this.encryptor,
    required this.decryptor,
  });

  @override
  Uint8List get iv => encryptor.iv;

  /// Creates AES cipher in XTS mode.
  ///
  /// Parameters:
  /// - [key] Combined key for the message and tweak (either 32 or 64 bytes).
  /// - [iv] The initial tweak value (16-bytes).
  factory AESInXTSMode(List<int> key, [List<int>? iv]) {
    if (![32, 48, 64].contains(key.length)) {
      throw StateError('Invalid key size: ${key.length}');
    }
    iv ??= randomBytes(16);
    if (iv.length != 16) {
      throw StateError('The iv (tweak) must be 16-bytes');
    }
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var mid = key8.length >>> 1;
    var ekey = key8.sublist(0, mid);
    var tkey = key8.sublist(mid);
    return AESInXTSMode._(
      encryptor: AESInXTSModeEncrypt(ekey, tkey, iv8),
      decryptor: AESInXTSModeDecrypt(ekey, tkey, iv8),
    );
  }

  /// Creates AES cipher in XTS mode using sector address.
  ///
  /// Parameters:
  /// - [key] Combined key for the message and tweak (either 32 or 64 bytes).
  /// - [sector] The sector number for the data. For disk encryption, it can be
  ///   the Logical Block Address (LBA). For file encryption, it can be a
  ///   counter or offset within the file. For network transmission, it can be
  ///   packet number or frame number. The initial tweak value is calculated
  ///   this value.
  factory AESInXTSMode.fromSector(List<int> key, Nonce64 sector) {
    var sector8 = sector.bytes;
    var tweak = Uint8List(16);
    for (int i = 0; i < 8; ++i) {
      tweak[i] = sector8[i];
    }
    return AESInXTSMode(key, tweak);
  }
}
