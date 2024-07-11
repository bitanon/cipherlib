// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/padding.dart';
import 'package:cipherlib/src/core/cipher_sink.dart';
import 'package:cipherlib/src/core/salted_cipher.dart';
import 'package:hashlib/hashlib.dart';

import '_core.dart';

/// Multiply [M] and [H] in 128-bit Galois field.
///
/// Returns `M * H mod P` in GF(2^128), where
/// `P = 0xE1000000000000000000000000000`
void _multiply128(Uint8List M, Uint8List H) {
  int i, j, k, x, y, c;
  var v = H.sublist(0);
  var z = Uint8List(16);
  for (i = 0; i < 16; i++) {
    x = M[i];
    for (k = 0x80; k > 0; k >>>= 1) {
      // add M
      if (x & k != 0) {
        for (j = 0; j < 16; ++j) {
          z[j] ^= v[j];
        }
      }
      // shift right
      c = 0;
      for (j = 0; j < 16; j++) {
        y = v[j];
        v[j] = c | (y >>> 1);
        c = (y & 1) << 7;
      }
      // modulus
      if (c != 0) {
        v[0] ^= 0xE1;
      }
    }
  }
  for (i = 0; i < 16; ++i) {
    M[i] = z[i];
  }
}

/// This implementation is derived from [NIST GCM Specification][spec].
///
/// [spec]: https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
abstract class _AESInGCMModeSinkBase extends CipherSink {
  _AESInGCMModeSinkBase(
    this._key,
    this._iv,
    this._aad,
  ) {
    reset();
  }

  int _pos = 0;
  int _rpos = 0;
  bool _closed = false;
  int _aadLength = 0;
  int _dataLength = 0;
  final Uint8List _key;
  final Uint8List _iv;
  final Iterable<int>? _aad;
  final _counter = Uint8List(16);
  final _block = Uint8List(16); // 128-bit
  final _tag = Uint8List(16);
  final _first = Uint8List(16);
  final _hkey = Uint8List(16); // key for GHASH
  late final _key32 = Uint32List.view(_key.buffer);
  late final _block32 = Uint32List.view(_block.buffer);
  late final _first32 = Uint32List.view(_first.buffer);
  late final _hkey32 = Uint32List.view(_hkey.buffer);
  late final _xkey32 = AESCore.$expandEncryptionKey(_key32);

  @override
  bool get closed => _closed;

  @override
  void reset() {
    int i, n;

    _pos = 0;
    _rpos = 0;
    _aadLength = 0;
    _dataLength = 0;
    _closed = false;

    // GHASH init
    for (i = 0; i < 16; ++i) {
      _tag[i] = 0;
      _hkey[i] = 0;
    }
    AESCore.$encrypt(_hkey32, _xkey32);

    // build counter 0
    if (_iv.lengthInBytes == 12) {
      // 96-bit nonce
      for (i = 0; i < 12; ++i) {
        _counter[i] = _iv[i];
      }
      _counter[12] = 0;
      _counter[13] = 0;
      _counter[14] = 0;
      _counter[15] = 1;
    } else {
      // nonce of other length
      n = 0;
      for (int x in _iv) {
        _tag[n++] ^= x;
        if (n == 16) {
          _multiply128(_tag, _hkey);
          n = 0;
        }
      }
      if (n > 0) {
        _multiply128(_tag, _hkey);
      }
      _serialize64(0, _iv.length);
      _multiply128(_tag, _hkey);
      for (i = 0; i < 16; ++i) {
        _counter[i] = _tag[i];
        _tag[i] = 0;
      }
    }

    // encrypt counter 0 for mac
    for (i = 0; i < 16; ++i) {
      _first[i] = _counter[i];
    }
    AESCore.$encrypt(_first32, _xkey32);

    // add aad
    if (_aad != null) {
      n = 0;
      for (int x in _aad!) {
        _tag[n++] ^= x;
        if (n == 16) {
          _multiply128(_tag, _hkey);
          _aadLength += 16;
          n = 0;
        }
      }
      if (n > 0) {
        _multiply128(_tag, _hkey);
        _aadLength += n;
      }
    }
  }

  void _nextBlock() {
    int i;
    for (i = 15; i >= 12; i--) {
      _counter[i]++;
      if (_counter[i] != 0) break;
    }
    for (i = 0; i < 16; ++i) {
      _block[i] = _counter[i];
    }
    AESCore.$encrypt(_block32, _xkey32);
  }

  void _serialize64(int a, int b) {
    a <<= 3;
    b <<= 3;
    _tag[0] ^= a >>> 56;
    _tag[1] ^= a >>> 48;
    _tag[2] ^= a >>> 40;
    _tag[3] ^= a >>> 32;
    _tag[4] ^= a >>> 24;
    _tag[5] ^= a >>> 16;
    _tag[6] ^= a >>> 8;
    _tag[7] ^= a;
    _tag[8] ^= b >>> 56;
    _tag[9] ^= b >>> 48;
    _tag[10] ^= b >>> 40;
    _tag[11] ^= b >>> 32;
    _tag[12] ^= b >>> 24;
    _tag[13] ^= b >>> 16;
    _tag[14] ^= b >>> 8;
    _tag[15] ^= b;
  }
}

/// The sink used for both encryption and decryption by the
/// [AESInGCMModeEncrypt] algorithm.
class AESInGCMModeEncryptSink extends _AESInGCMModeSinkBase {
  AESInGCMModeEncryptSink(
    Uint8List key,
    Uint8List iv,
    Iterable<int>? aad, [
    this._tagSize = 16,
  ]) : super(key, iv, aad) {
    if (_tagSize < 1) {
      throw StateError('Tag size must be at least 1');
    } else if (_tagSize > 16) {
      throw StateError('Tag size must be at most 16');
    }
  }

  final int _tagSize;

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
    _dataLength += end - start;

    int i, j, n, p;
    n = end - start;
    if (last) n += _tagSize;
    var output = Uint8List(n);

    p = 0;
    for (i = start; i < end; ++i) {
      if (_pos == 0) {
        _nextBlock();
      }
      output[p] = _block[_pos] ^ data[i];
      _tag[_pos] ^= output[p++];
      _pos++;
      if (_pos == 16) {
        _multiply128(_tag, _hkey);
        _pos = 0;
      }
    }

    if (last) {
      if (_pos > 0) {
        _multiply128(_tag, _hkey);
      }
      _serialize64(_aadLength, _dataLength);
      _multiply128(_tag, _hkey);
      for (j = 0; j < _tagSize; ++j) {
        _tag[j] ^= _first[j];
        output[p++] = _tag[j];
      }
    }

    return output;
  }
}

/// The sink used for both encryption and decryption by the
/// [AESInGCMModeDecrypt] algorithm.
class AESInGCMModeDecryptSink extends _AESInGCMModeSinkBase {
  AESInGCMModeDecryptSink(
    Uint8List key,
    Uint8List iv,
    Iterable<int>? aad, [
    this._tagSize = 16,
  ]) : super(key, iv, aad) {
    if (_tagSize < 1) {
      throw StateError('Tag size must be at least 1');
    } else if (_tagSize > 16) {
      throw StateError('Tag size must be at most 16');
    }
  }

  final int _tagSize;
  late final _residue = Uint8List(_tagSize);

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

    int i, j, p;
    var output = Uint8List(end - start);

    p = 0;
    for (i = start; i < end; ++i) {
      if (_dataLength >= _tagSize) {
        if (_pos == 0) {
          _nextBlock();
        }
        output[p++] = _block[_pos] ^ _residue[_rpos];
        _tag[_pos] ^= _residue[_rpos];
        _pos++;
        if (_pos == 16) {
          _multiply128(_tag, _hkey);
          _pos = 0;
        }
      }
      _residue[_rpos++] = data[i];
      _dataLength++;
      if (_rpos == _tagSize) {
        _rpos = 0;
      }
    }

    if (last) {
      _dataLength -= _tagSize;
      if (_dataLength < 0) {
        throw StateError('Invalid message size');
      }
      if (_pos > 0) {
        _multiply128(_tag, _hkey);
      }
      _serialize64(_aadLength, _dataLength);
      _multiply128(_tag, _hkey);
      for (j = 0; j < _tagSize; ++j) {
        _tag[j] ^= _first[j];
      }
      for (j = 0; j < _tagSize; ++j) {
        if (_tag[j] != _residue[_rpos++]) {
          throw StateError('Message authentication check failed');
        }
        if (_rpos == _tagSize) {
          _rpos = 0;
        }
      }
    }

    if (p == 0) {
      return Uint8List(0);
    } else if (p == output.length) {
      return output;
    } else {
      return output.sublist(0, p);
    }
  }
}

/// Provides AES cipher in GCM mode for encryption.
class AESInGCMModeEncrypt extends SaltedCipher {
  @override
  final String name = "AES#encrypt/GCM";

  /// Key for the cipher
  final Uint8List key;

  /// The length of the message authentication tag in bytes
  final int tagSize;

  /// Additional authenticated data for AEAD construction
  final Iterable<int>? aad;

  const AESInGCMModeEncrypt(
    this.key,
    Uint8List iv, {
    this.aad,
    this.tagSize = 16,
  }) : super(iv);

  @override
  @pragma('vm:prefer-inline')
  AESInGCMModeEncryptSink createSink() =>
      AESInGCMModeEncryptSink(key, iv, aad, tagSize);
}

/// Provides AES cipher in GCM mode for decryption.
class AESInGCMModeDecrypt extends SaltedCipher {
  @override
  final String name = "AES#decrypt/GCM";

  /// Key for the cipher
  final Uint8List key;

  /// The length of the message authentication tag in bytes
  final int tagSize;

  /// Additional authenticated data for AEAD construction
  final Iterable<int>? aad;

  const AESInGCMModeDecrypt(
    this.key,
    Uint8List iv, {
    this.aad,
    this.tagSize = 16,
  }) : super(iv);

  @override
  @pragma('vm:prefer-inline')
  AESInGCMModeDecryptSink createSink() =>
      AESInGCMModeDecryptSink(key, iv, aad, tagSize);
}

/// Provides encryption and decryption for AES cipher in GCM mode.
class AESInGCMMode extends SaltedCollateCipher {
  @override
  String get name => "AES/GCM/${Padding.none.name}";

  @override
  final AESInGCMModeEncrypt encryptor;

  @override
  final AESInGCMModeDecrypt decryptor;

  const AESInGCMMode._({
    required this.encryptor,
    required this.decryptor,
  });

  /// Creates AES cipher in GCM mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] A random initialization vector or salt of any length
  /// - [aad] Additional authentication data for tag generation
  /// - [tagSize] The length of the message authentication tag in bytes
  factory AESInGCMMode(
    List<int> key, {
    List<int>? iv,
    Iterable<int>? aad,
    int tagSize = 16,
  }) {
    iv ??= randomBytes(12);
    var iv8 = iv is Uint8List ? iv : Uint8List.fromList(iv);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    return AESInGCMMode._(
      encryptor: AESInGCMModeEncrypt(key8, iv8, aad: aad, tagSize: tagSize),
      decryptor: AESInGCMModeDecrypt(key8, iv8, aad: aad, tagSize: tagSize),
    );
  }
}
