// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../../core/aes.dart';
import '../../core/cipher.dart';
import '../../utils/typed_data.dart';
import '../padding.dart';

/// This implementation is derived from [NIST GCM Specification][spec].
///
/// [spec]: https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
class AESInGCMModeCipherCore {
  final int tagSize;
  final Uint8List iv;
  final Uint8List key;
  final Uint8List? aad;

  AESInGCMModeCipherCore(
    this.key,
    this.iv,
    this.aad, [
    this.tagSize = 16,
  ]);

  int aadLength = 0;

  final tag32 = Uint32List(4);
  final block32 = Uint32List(4); // 128-bit
  final first32 = Uint32List(4);
  final counter32 = Uint32List(4);
  final hcache32 = Uint32List(512); // 16 * 128 bytes

  late final iv32 = Uint32List.view(iv.buffer);
  late final tag = Uint8List.view(tag32.buffer);
  late final key32 = Uint32List.view(key.buffer);
  late final block = Uint8List.view(block32.buffer);
  late final first = Uint8List.view(first32.buffer);
  late final counter = Uint8List.view(counter32.buffer);
  late final xkey32 = AESCore.$expandEncryptionKey(key32);

  /// Returns `T ^ (a << 3) ^ (b << 3)`
  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  static void _xor128(Uint32List T, int a, int b) {
    T[0] ^= AESCore.$swap32(a >>> 29);
    T[1] ^= AESCore.$swap32(a << 3);
    T[2] ^= AESCore.$swap32(b >>> 29);
    T[3] ^= AESCore.$swap32(b << 3);
  }

  /// Returns `(M * H) mod P` in **GF(`2^128`)**,
  /// where `P` = 0xE1000000000000000000000000000
  @pragma('vm:prefer-inline')
  static void _multiply128(Uint32List M, Uint32List H) {
    int i, x, b, s;
    int t0, t1, t2, t3;
    i = 0;
    t0 = t1 = t2 = t3 = 0;
    for (x in M) {
      for (s = 128; x != 0; x >>>= 8, s -= 32) {
        for (b = 0x80; b != 0; b >>>= 1, i += 4) {
          if (x & b != 0) {
            t0 ^= H[i];
            t1 ^= H[i + 1];
            t2 ^= H[i + 2];
            t3 ^= H[i + 3];
          }
        }
      }
      i += s;
    }
    M[0] = t0;
    M[1] = t1;
    M[2] = t2;
    M[3] = t3;
  }

  // Increment a 32-bit counter in little-endian order
  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  static void _increment32(Uint8List counter) {
    counter[15]++;
    if (counter[15] == 0) {
      counter[14]++;
      if (counter[14] == 0) {
        counter[13]++;
        if (counter[13] == 0) {
          counter[12]++;
        }
      }
    }
  }

  void initialize() {
    int i, j, y, c;

    // GHASH hash table generation
    AESCore.$encrypt(hcache32, xkey32);
    hcache32[0] = AESCore.$swap32(hcache32[0]);
    hcache32[1] = AESCore.$swap32(hcache32[1]);
    hcache32[2] = AESCore.$swap32(hcache32[2]);
    hcache32[3] = AESCore.$swap32(hcache32[3]);
    for (i = 4; i < 512; i += 4) {
      // shift right 1-bit over 16 bytes in the table row
      c = 0;
      // 0...3 of the current row
      y = hcache32[i - 4];
      hcache32[i] = c | ((y >>> 1) & 0x7F7F7F7F) | ((y & 0x00010101) << 15);
      c = (y >>> 17) & 0x80;
      // 4...7 of the current row
      y = hcache32[i - 3];
      hcache32[i + 1] = c | ((y >>> 1) & 0x7F7F7F7F) | ((y & 0x00010101) << 15);
      c = (y >>> 17) & 0x80;
      // 8...11 of the current row
      y = hcache32[i - 2];
      hcache32[i + 2] = c | ((y >>> 1) & 0x7F7F7F7F) | ((y & 0x00010101) << 15);
      c = (y >>> 17) & 0x80;
      // 12...15 of the current row
      y = hcache32[i - 1];
      hcache32[i + 3] = c | ((y >>> 1) & 0x7F7F7F7F) | ((y & 0x00010101) << 15);
      c = (y >>> 17) & 0x80;
      // modulus (c is either 0x00 or 0x80).
      hcache32[i] ^= (-(c >>> 7)) & 0xE1;
    }

    // build first counter from initialization vector
    if (iv.length == 12) {
      // if IV is 12 bytes, use the first 9 bytes as the counter
      counter32[0] = iv32[0];
      counter32[1] = iv32[1];
      counter32[2] = iv32[2];
      counter32[3] = 0x1000000;
    } else {
      // otherwise, use the entire IV as the counter
      for (i = 0; i + 4 < iv32.length; i += 4) {
        counter32[0] ^= iv32[i];
        counter32[1] ^= iv32[i + 1];
        counter32[2] ^= iv32[i + 2];
        counter32[3] ^= iv32[i + 3];
        _multiply128(counter32, hcache32);
      }
      i <<= 2;
      for (j = 0; i + j < iv.length; ++j) {
        counter[j] ^= iv[i + j];
      }
      if (j > 0) {
        _multiply128(counter32, hcache32);
      }
      _xor128(counter32, 0, iv.length);
      _multiply128(counter32, hcache32);
    }

    // encrypt first counter for message authentication code
    first32[0] = counter32[0];
    first32[1] = counter32[1];
    first32[2] = counter32[2];
    first32[3] = counter32[3];
    AESCore.$encryptLE(first32, xkey32);

    // process additional authenticated data
    if (aad != null) {
      aadLength = aad!.length;
      final aad32 = Uint32List.view(aad!.buffer);
      for (i = 0; i + 4 <= aad32.length; i += 4) {
        tag32[0] ^= aad32[i];
        tag32[1] ^= aad32[i + 1];
        tag32[2] ^= aad32[i + 2];
        tag32[3] ^= aad32[i + 3];
        _multiply128(tag32, hcache32);
      }
      i <<= 2;
      for (j = 0; i + j < aadLength; ++j) {
        tag[j] ^= aad![i + j];
      }
      if (j > 0) {
        _multiply128(tag32, hcache32);
      }
    }
  }

  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  void _nextBlock() {
    _increment32(counter);
    block32[0] = counter32[0];
    block32[1] = counter32[1];
    block32[2] = counter32[2];
    block32[3] = counter32[3];
    AESCore.$encryptLE(block32, xkey32);
  }

  Uint8List encrypt(List<int> message) {
    int i, j, n;
    int x0, x1, x2, x3;

    n = message.length;
    final output = Uint8List(n + tagSize);
    final output32 = Uint32List.view(output.buffer);

    for (i = 0; i + 16 <= n; i += 16) {
      _nextBlock();

      x0 = block32[0] ^
          (message[i + 0]) ^
          (message[i + 1] << 8) ^
          (message[i + 2] << 16) ^
          (message[i + 3] << 24);
      x1 = block32[1] ^
          (message[i + 4]) ^
          (message[i + 5] << 8) ^
          (message[i + 6] << 16) ^
          (message[i + 7] << 24);
      x2 = block32[2] ^
          (message[i + 8]) ^
          (message[i + 9] << 8) ^
          (message[i + 10] << 16) ^
          (message[i + 11] << 24);
      x3 = block32[3] ^
          (message[i + 12]) ^
          (message[i + 13] << 8) ^
          (message[i + 14] << 16) ^
          (message[i + 15] << 24);

      tag32[0] ^= x0;
      tag32[1] ^= x1;
      tag32[2] ^= x2;
      tag32[3] ^= x3;
      _multiply128(tag32, hcache32);

      j = i >>> 2;
      output32[j + 0] = x0;
      output32[j + 1] = x1;
      output32[j + 2] = x2;
      output32[j + 3] = x3;
    }

    if (i < n) {
      _nextBlock();
      for (j = 0; i + j < n; ++j) {
        output[i + j] = block[j] ^ message[i + j];
        tag[j] ^= output[i + j];
      }
      _multiply128(tag32, hcache32);
    }

    _xor128(tag32, aadLength, n);
    _multiply128(tag32, hcache32);
    for (j = 0; j < tagSize; ++j) {
      tag[j] ^= first[j];
      output[n + j] = tag[j];
    }

    return output;
  }

  Stream<Uint8List> encryptStream(Stream<List<int>> stream) async* {
    int i, j;
    int pos = 0;
    int msgLength = 0;
    final output32 = Uint32List(4);
    final output = Uint8List.view(output32.buffer);

    await for (final chunk in stream) {
      if (chunk.isEmpty) {
        continue;
      }
      msgLength += chunk.length;
      for (i = 0; i < chunk.length; ++i) {
        if (pos == 0) {
          _nextBlock();
        }
        output[pos] = block[pos] ^ chunk[i];
        pos++;
        if (pos == 16) {
          tag32[0] ^= output32[0];
          tag32[1] ^= output32[1];
          tag32[2] ^= output32[2];
          tag32[3] ^= output32[3];
          _multiply128(tag32, hcache32);
          yield output.sublist(0);
          pos = 0;
        }
      }
    }

    if (pos > 0) {
      for (j = 0; j < pos; ++j) {
        tag[j] ^= output[j];
      }
      _multiply128(tag32, hcache32);
      yield output.sublist(0, pos);
    }

    _xor128(tag32, aadLength, msgLength);
    _multiply128(tag32, hcache32);
    for (i = 0; i < tagSize; ++i) {
      tag[i] ^= first[i];
    }
    yield tag.sublist(0, tagSize);
  }

  Uint8List decrypt(List<int> message) {
    int i, j, n;
    int m0, m1, m2, m3;

    n = message.length - tagSize;
    if (n < 0) {
      throw StateError('Invalid message size');
    }
    final output = Uint8List(n);
    final output32 = Uint32List.view(output.buffer);

    for (i = 0; i + 16 <= n; i += 16) {
      _nextBlock();

      m0 = (message[i + 0]) ^
          (message[i + 1] << 8) ^
          (message[i + 2] << 16) ^
          (message[i + 3] << 24);
      m1 = (message[i + 4]) ^
          (message[i + 5] << 8) ^
          (message[i + 6] << 16) ^
          (message[i + 7] << 24);
      m2 = (message[i + 8]) ^
          (message[i + 9] << 8) ^
          (message[i + 10] << 16) ^
          (message[i + 11] << 24);
      m3 = (message[i + 12]) ^
          (message[i + 13] << 8) ^
          (message[i + 14] << 16) ^
          (message[i + 15] << 24);

      tag32[0] ^= m0;
      tag32[1] ^= m1;
      tag32[2] ^= m2;
      tag32[3] ^= m3;
      _multiply128(tag32, hcache32);

      j = i >>> 2;
      output32[j + 0] = block32[0] ^ m0;
      output32[j + 1] = block32[1] ^ m1;
      output32[j + 2] = block32[2] ^ m2;
      output32[j + 3] = block32[3] ^ m3;
    }

    // process final partial block
    if (i < n) {
      _nextBlock();
      for (j = 0; i + j < n; ++j) {
        output[i + j] = block[j] ^ message[i + j];
        tag[j] ^= message[i + j];
      }
      _multiply128(tag32, hcache32);
    }

    // finalize tag
    _xor128(tag32, aadLength, n);
    _multiply128(tag32, hcache32);
    for (j = 0; j < tagSize; ++j) {
      tag[j] ^= first[j];
    }

    // verify tag
    bool valid = true;
    for (j = 0; j < tagSize; ++j) {
      if (tag[j] != message[n + j]) {
        valid = false;
      }
    }
    if (!valid) {
      throw StateError('Message authentication check failed');
    }

    return output;
  }

  Stream<Uint8List> decryptStream(Stream<List<int>> stream) async* {
    int i;
    int r = 0;
    int pos = 0;
    int rpos = 0;
    int msgLength = 0;

    final ring = Uint8List(tagSize);
    final output32 = Uint32List(4);
    final output = Uint8List.view(output32.buffer);

    _nextBlock();
    await for (final chunk in stream) {
      msgLength += chunk.length;
      for (i = 0; i < chunk.length; ++i) {
        if (rpos < tagSize) {
          ring[rpos++] = chunk[i];
          continue;
        }
        output[pos] = block[pos] ^ ring[r];
        tag[pos] ^= ring[r];
        ring[r] = chunk[i];
        pos++;
        r++;
        if (r == tagSize) {
          r = 0;
        }
        if (pos == 16) {
          _multiply128(tag32, hcache32);
          yield output.sublist(0);
          _nextBlock();
          pos = 0;
        }
      }
    }

    if (msgLength < tagSize) {
      throw StateError('Invalid message size');
    }
    msgLength -= tagSize;

    // finalize tag
    if (pos > 0) {
      _multiply128(tag32, hcache32);
      yield output.sublist(0, pos);
    }
    _xor128(tag32, aadLength, msgLength);
    _multiply128(tag32, hcache32);
    for (i = 0; i < tagSize; ++i) {
      tag[i] ^= first[i];
    }

    // verify tag
    bool valid = true;
    for (i = 0; i < tagSize; ++i, ++r) {
      if (r == tagSize) {
        r = 0;
      }
      if (tag[i] != ring[r]) {
        valid = false;
      }
    }
    if (!valid) {
      throw StateError('Message authentication check failed');
    }
  }
}

/// Provides AES cipher in GCM mode for encryption.
class AESInGCMModeEncrypt extends StreamCipher with SaltedCipher {
  @override
  String get name => "AES#encrypt/GCM/${Padding.none.name}";

  /// Key for the cipher
  final Uint8List key;

  @override
  final Uint8List iv;

  /// The length of the message authentication tag in bytes
  final int tagSize;

  /// Additional authenticated data for AEAD construction
  final Uint8List? aad;

  const AESInGCMModeEncrypt(
    this.key,
    this.iv, {
    this.aad,
    this.tagSize = 16,
  });

  @override
  Uint8List convert(List<int> message) {
    final core = AESInGCMModeCipherCore(key, iv, aad, tagSize)..initialize();
    return core.encrypt(message);
  }

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) async* {
    final core = AESInGCMModeCipherCore(key, iv, aad, tagSize)..initialize();
    yield* core.encryptStream(stream);
  }
}

/// Provides AES cipher in GCM mode for decryption.
class AESInGCMModeDecrypt extends StreamCipher with SaltedCipher {
  @override
  String get name => "AES#decrypt/GCM/${Padding.none.name}";

  /// Key for the cipher
  final Uint8List key;

  @override
  final Uint8List iv;

  /// The length of the message authentication tag in bytes
  final int tagSize;

  /// Additional authenticated data for AEAD construction
  final Uint8List? aad;

  const AESInGCMModeDecrypt(
    this.key,
    this.iv, {
    this.aad,
    this.tagSize = 16,
  });

  @override
  Uint8List convert(List<int> message) {
    final core = AESInGCMModeCipherCore(key, iv, aad, tagSize)..initialize();
    return core.decrypt(message);
  }

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) async* {
    final core = AESInGCMModeCipherCore(key, iv, aad, tagSize)..initialize();
    yield* core.decryptStream(stream);
  }
}

/// Provides encryption and decryption for AES cipher in GCM mode.
class AESInGCMMode extends StreamCipherPair with SaltedCipher {
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

  @override
  Uint8List get iv => encryptor.iv;

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
    if (tagSize < 1 || tagSize > 16) {
      throw StateError('Tag size must be between 1 and 16');
    }

    final key8 = toUint8List(key);
    if (key8.length != 16 && key8.length != 24 && key8.length != 32) {
      throw StateError('Key must be 16, 24, or 32 bytes');
    }

    iv ??= randomBytes(12);
    final iv8 = toUint8List(iv);

    final aad8 = aad != null ? toUint8List(aad) : null;

    return AESInGCMMode._(
      encryptor: AESInGCMModeEncrypt(
        key8,
        iv8,
        aad: aad8,
        tagSize: tagSize,
      ),
      decryptor: AESInGCMModeDecrypt(
        key8,
        iv8,
        aad: aad8,
        tagSize: tagSize,
      ),
    );
  }
}
