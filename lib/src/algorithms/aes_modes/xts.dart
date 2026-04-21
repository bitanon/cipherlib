// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../../core/aes.dart';
import '../../core/cipher.dart';
import '../../utils/nonce.dart';
import '../../utils/typed_data.dart';
import '../padding.dart';

/// Multiply by `alpha` = `0x87` in 128-bit Galois Field
@pragma('vm:prefer-inline')
@pragma('dart2js:tryInline')
void _multiplyAlpha(Uint32List T) {
  int t0, t1, t2, t3, p;

  t0 = T[0];
  t1 = T[1];
  t2 = T[2];
  t3 = T[3];

  p = t3 >>> 31;
  t3 = (t3 << 1) ^ (t2 >>> 31);
  t2 = (t2 << 1) ^ (t1 >>> 31);
  t1 = (t1 << 1) ^ (t0 >>> 31);
  t0 = (t0 << 1) ^ (p * 0x87);

  T[0] = t0;
  T[1] = t1;
  T[2] = t2;
  T[3] = t3;
}

/// Provides encryption for AES cipher in XTS mode.
///
/// This implementation is derived from [1619-2018 - IEEE Standard for
/// Cryptographic Protection of Data on Block-Oriented Storage Devices][spec].
///
/// [spec]: https://ieeexplore.ieee.org/document/8637988
class AESInXTSModeEncrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#encrypt/XTS/${Padding.none.name}";

  /// Key for the plaintext encryption
  final Uint8List key1; // 16, 24, or 32-bytes

  /// Key for the tweak encryption
  final Uint8List key2; // 16, 24, or 32-bytes

  /// The tweak for the XTS mode
  @override
  final Uint8List iv; // 16-bytes

  const AESInXTSModeEncrypt(
    this.key1,
    this.key2,
    this.iv,
  );

  @override
  Uint8List convert(List<int> message) {
    int i, j, n, pos;
    n = message.length;
    if (n < 16) {
      throw StateError('The message must be at least 16 bytes');
    }

    final output = Uint8List(n);
    final tweak32 = Uint32List(4);
    final block32 = Uint32List(4); // 128-bit
    final iv32 = Uint32List.view(iv.buffer);
    final ekey32 = Uint32List.view(key1.buffer);
    final tkey32 = Uint32List.view(key2.buffer);
    final block = Uint8List.view(block32.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xtkey32 = AESCore.$expandEncryptionKey(tkey32);
    final xekey32 = AESCore.$expandEncryptionKey(ekey32);

    // encrypt tweak
    tweak32[0] = iv32[0];
    tweak32[1] = iv32[1];
    tweak32[2] = iv32[2];
    tweak32[3] = iv32[3];
    AESCore.$encryptLE(tweak32, xtkey32);

    // full blocks except last block when it is partial
    for (i = 0; i + 16 <= n; i += 16) {
      block32[0] = (message[i + 0] ^
          (message[i + 1] << 8) ^
          (message[i + 2] << 16) ^
          (message[i + 3] << 24));
      block32[1] = ((message[i + 4]) ^
          (message[i + 5] << 8) ^
          (message[i + 6] << 16) ^
          message[i + 7] << 24);
      block32[2] = (message[i + 8] ^
          (message[i + 9] << 8) ^
          (message[i + 10] << 16) ^
          (message[i + 11] << 24));
      block32[3] = (message[i + 12] ^
          (message[i + 13] << 8) ^
          (message[i + 14] << 16) ^
          (message[i + 15] << 24));

      block32[0] ^= tweak32[0];
      block32[1] ^= tweak32[1];
      block32[2] ^= tweak32[2];
      block32[3] ^= tweak32[3];
      AESCore.$encryptLE(block32, xekey32);
      block32[0] ^= tweak32[0];
      block32[1] ^= tweak32[1];
      block32[2] ^= tweak32[2];
      block32[3] ^= tweak32[3];

      j = i >>> 2;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];
      output32[j + 2] = block32[2];
      output32[j + 3] = block32[3];

      _multiplyAlpha(tweak32);
    }

    // last block when it is partial
    if (i < n) {
      for (pos = 0; i + pos < n; pos++) {
        output[i + pos] = block[pos];
        block[pos] = message[i + pos];
      }

      block32[0] ^= tweak32[0];
      block32[1] ^= tweak32[1];
      block32[2] ^= tweak32[2];
      block32[3] ^= tweak32[3];
      AESCore.$encryptLE(block32, xekey32);
      block32[0] ^= tweak32[0];
      block32[1] ^= tweak32[1];
      block32[2] ^= tweak32[2];
      block32[3] ^= tweak32[3];

      j = (i >>> 2) - 4;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];
      output32[j + 2] = block32[2];
      output32[j + 3] = block32[3];
    }

    return output;
  }
}

/// Provides decryption for AES cipher in XTS mode.
///
/// This implementation is derived from [1619-2018 - IEEE Standard for
/// Cryptographic Protection of Data on Block-Oriented Storage Devices][spec].
///
/// [spec]: https://ieeexplore.ieee.org/document/8637988
class AESInXTSModeDecrypt extends Cipher with SaltedCipher {
  @override
  String get name => "AES#decrypt/XTS/${Padding.none.name}";

  /// Key for the ciphertext decryption
  final Uint8List key1; // 16, 24, or 32-bytes

  /// Key for the tweak encryption
  final Uint8List key2; // 16, 24, or 32-bytes

  /// The tweak for the XTS mode
  @override
  final Uint8List iv; // 16-bytes

  const AESInXTSModeDecrypt(
    this.key1,
    this.key2,
    this.iv,
  );

  @override
  Uint8List convert(List<int> message) {
    int i, j, n, pos;
    n = message.length;
    if (n < 16) {
      throw StateError('The message must be at least 16 bytes');
    }

    final output = Uint8List(n);
    final temp32 = Uint32List(4);
    final tweak32 = Uint32List(4);
    final block32 = Uint32List(4); // 128-bit
    final iv32 = Uint32List.view(iv.buffer);
    final dkey32 = Uint32List.view(key1.buffer);
    final tkey32 = Uint32List.view(key2.buffer);
    final block = Uint8List.view(block32.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xtkey32 = AESCore.$expandEncryptionKey(tkey32);
    final xdkey32 = AESCore.$expandDecryptionKey(dkey32);

    // encrypt tweak
    tweak32[0] = iv32[0];
    tweak32[1] = iv32[1];
    tweak32[2] = iv32[2];
    tweak32[3] = iv32[3];
    AESCore.$encryptLE(tweak32, xtkey32);

    // full blocks except last block when it is partial
    for (i = 0; i + 16 <= n; i += 16) {
      block32[0] = (message[i + 0] ^
          (message[i + 1] << 8) ^
          (message[i + 2] << 16) ^
          (message[i + 3] << 24));
      block32[1] = ((message[i + 4]) ^
          (message[i + 5] << 8) ^
          (message[i + 6] << 16) ^
          message[i + 7] << 24);
      block32[2] = (message[i + 8] ^
          (message[i + 9] << 8) ^
          (message[i + 10] << 16) ^
          (message[i + 11] << 24));
      block32[3] = (message[i + 12] ^
          (message[i + 13] << 8) ^
          (message[i + 14] << 16) ^
          (message[i + 15] << 24));

      if (i + 16 < n && n < i + 32) {
        // this is 2nd to last block when last block is partial
        temp32[0] = tweak32[0];
        temp32[1] = tweak32[1];
        temp32[2] = tweak32[2];
        temp32[3] = tweak32[3];
        _multiplyAlpha(tweak32);
      }

      block32[0] ^= tweak32[0];
      block32[1] ^= tweak32[1];
      block32[2] ^= tweak32[2];
      block32[3] ^= tweak32[3];
      AESCore.$decryptLE(block32, xdkey32);
      block32[0] ^= tweak32[0];
      block32[1] ^= tweak32[1];
      block32[2] ^= tweak32[2];
      block32[3] ^= tweak32[3];

      j = i >>> 2;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];
      output32[j + 2] = block32[2];
      output32[j + 3] = block32[3];

      _multiplyAlpha(tweak32);
    }

    // last block when it is partial
    if (i < n) {
      for (pos = 0; i + pos < n; pos++) {
        output[i + pos] = block[pos];
        block[pos] = message[i + pos];
      }

      block32[0] ^= temp32[0];
      block32[1] ^= temp32[1];
      block32[2] ^= temp32[2];
      block32[3] ^= temp32[3];
      AESCore.$decryptLE(block32, xdkey32);
      block32[0] ^= temp32[0];
      block32[1] ^= temp32[1];
      block32[2] ^= temp32[2];
      block32[3] ^= temp32[3];

      j = (i >>> 2) - 4;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];
      output32[j + 2] = block32[2];
      output32[j + 3] = block32[3];
    }

    return output;
  }
}

/// Provides encryption and decryption for AES cipher in XTS mode.
class AESInXTSMode extends CollateCipher with SaltedCipher {
  @override
  String get name => "AES/XTS/${Padding.none.name}";

  @override
  final AESInXTSModeEncrypt encryptor;

  @override
  final AESInXTSModeDecrypt decryptor;

  /// The tweak for the XTS mode
  @override
  Uint8List get iv => encryptor.iv;

  const AESInXTSMode._({
    required this.encryptor,
    required this.decryptor,
  });

  /// Creates AES cipher in XTS mode.
  ///
  /// Parameters:
  /// - [key] Combined key for the message and tweak (either 32 or 64 bytes).
  /// - [tweak] The initial tweak value (16-bytes).
  factory AESInXTSMode(List<int> key, [List<int>? tweak]) {
    if (key.length != 32 && key.length != 48 && key.length != 64) {
      throw StateError('Invalid key size: ${key.length}');
    }
    tweak ??= randomBytes(16);
    if (tweak.length != 16) {
      throw StateError('The tweak (iv) must be 16-bytes');
    }
    var key8 = toUint8List(key);
    var iv8 = toUint8List(tweak);
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
