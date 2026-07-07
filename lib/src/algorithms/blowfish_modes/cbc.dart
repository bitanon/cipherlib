// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async' show Stream;
import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../../core/blowfish.dart';
import '../../core/cipher.dart';
import '../../utils/typed_data.dart';
import '../padding.dart';

/// Provides encryption for Blowfish cipher in CBC mode.
class BlowfishInCBCModeEncrypt extends StreamCipher with SaltedCipher {
  @override
  String get name => "Blowfish#encrypt/CBC/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Padding scheme for the input message
  final Padding padding;

  @override
  final Uint8List iv;

  const BlowfishInCBCModeEncrypt(
    this.key,
    this.iv, [
    this.padding = Padding.pkcs7,
  ]);

  @override
  Uint8List convert(List<int> message) {
    int i, j, pos;
    int n = message.length;
    int m = n + 8 - (n & 7);

    final output = Uint8List(m);
    final block32 = Uint32List(2); // 64-bit
    final iv32 = Uint32List.view(iv.buffer);
    final block = Uint8List.view(block32.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xkey32 = BlowfishCore.$expandKey(key);

    // initialize block with IV
    block32[0] = iv32[0];
    block32[1] = iv32[1];

    // process 8-byte blocks
    for (i = 0; i + 8 <= n; i += 8) {
      block32[0] ^= (message[i + 0] ^
          (message[i + 1] << 8) ^
          (message[i + 2] << 16) ^
          (message[i + 3] << 24));
      block32[1] ^= ((message[i + 4]) ^
          (message[i + 5] << 8) ^
          (message[i + 6] << 16) ^
          message[i + 7] << 24);

      BlowfishCore.$encryptLE(block32, xkey32);

      j = i >>> 2;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];
    }

    // process last block
    for (pos = 0; i + pos < n; ++pos) {
      block[pos] ^= message[i + pos];
    }
    final temp = block.sublist(pos);
    if (padding.pad(block, pos)) {
      for (j = 0; j < temp.length; ++j) {
        block[pos + j] ^= temp[j];
      }
      BlowfishCore.$encryptLE(block32, xkey32);

      j = i >>> 2;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];

      i += 8;
      pos = 0;
    }

    if (pos != 0) {
      throw StateError('Invalid input size');
    }

    if (i == m) {
      return output;
    } else {
      return output.sublist(0, i);
    }
  }

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) async* {
    int i, j;
    int pos = 0;

    final pending = Uint8List(8);
    final block32 = Uint32List(2); // 64-bit
    final iv32 = Uint32List.view(iv.buffer);
    final block = Uint8List.view(block32.buffer);
    final pending32 = Uint32List.view(pending.buffer);
    final xkey32 = BlowfishCore.$expandKey(key);

    // initialize block with IV
    block32[0] = iv32[0];
    block32[1] = iv32[1];

    await for (final chunk in stream) {
      for (i = 0; i < chunk.length; ++i) {
        pending[pos++] = chunk[i];
        if (pos == 8) {
          block32[0] ^= pending32[0];
          block32[1] ^= pending32[1];
          BlowfishCore.$encryptLE(block32, xkey32);
          yield block.sublist(0);
          pos = 0;
        }
      }
    }

    for (j = 0; j < pos; ++j) {
      block[j] ^= pending[j];
    }

    final temp = block.sublist(pos);
    if (padding.pad(block, pos)) {
      for (j = 0; j < temp.length; ++j) {
        block[pos + j] ^= temp[j];
      }
      BlowfishCore.$encryptLE(block32, xkey32);
      yield block.sublist(0);
      pos = 0;
    }

    if (pos != 0) {
      throw StateError('Invalid input size');
    }
  }
}

/// Provides decryption for Blowfish cipher in CBC mode.
class BlowfishInCBCModeDecrypt extends StreamCipher with SaltedCipher {
  @override
  String get name => "Blowfish#decrypt/CBC/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Padding scheme for the output message
  final Padding padding;

  @override
  final Uint8List iv;

  const BlowfishInCBCModeDecrypt(
    this.key,
    this.iv, [
    this.padding = Padding.pkcs7,
  ]);

  @override
  Uint8List convert(List<int> message) {
    int i, j, n;
    int s0, s1;
    int t0, t1;
    n = message.length;

    final output = Uint8List(n);
    final block32 = Uint32List(2); // 64-bit
    final iv32 = Uint32List.view(iv.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xkey32 = BlowfishCore.$expandKey(key);

    if ((n & 7) != 0) {
      throw StateError('Invalid input size');
    }

    s0 = iv32[0];
    s1 = iv32[1];

    // process 8-byte blocks
    for (i = 0; i + 8 <= n; i += 8) {
      t0 = block32[0] = (message[i + 0] ^
          (message[i + 1] << 8) ^
          (message[i + 2] << 16) ^
          (message[i + 3] << 24));
      t1 = block32[1] = ((message[i + 4]) ^
          (message[i + 5] << 8) ^
          (message[i + 6] << 16) ^
          message[i + 7] << 24);

      BlowfishCore.$decryptLE(block32, xkey32);

      j = i >>> 2;
      output32[j + 0] = block32[0] ^ s0;
      output32[j + 1] = block32[1] ^ s1;

      s0 = t0;
      s1 = t1;
    }

    return padding.unpad(output);
  }

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) async* {
    int i;
    int pos = 0;
    int s0, s1;
    int t0, t1;
    Uint8List? lastBlock;

    final pending = Uint8List(8);
    final block32 = Uint32List(2); // 64-bit
    final iv32 = Uint32List.view(iv.buffer);
    final block = Uint8List.view(block32.buffer);
    final pending32 = Uint32List.view(pending.buffer);
    final xkey32 = BlowfishCore.$expandKey(key);

    s0 = iv32[0];
    s1 = iv32[1];

    await for (final chunk in stream) {
      for (i = 0; i < chunk.length; ++i) {
        pending[pos++] = chunk[i];
        if (pos == 8) {
          if (lastBlock != null) {
            yield lastBlock;
          }

          t0 = block32[0] = pending32[0];
          t1 = block32[1] = pending32[1];
          BlowfishCore.$decryptLE(block32, xkey32);
          block32[0] ^= s0;
          block32[1] ^= s1;
          lastBlock = block.sublist(0);

          s0 = t0;
          s1 = t1;
          pos = 0;
        }
      }
    }

    if (pos != 0) {
      throw StateError('Invalid input size');
    }

    if (lastBlock != null) {
      yield padding.unpad(lastBlock);
    }
  }
}

/// Provides encryption and decryption for Blowfish cipher in CBC mode.
class BlowfishInCBCMode extends StreamCipherPair with SaltedCipher {
  @override
  String get name => "Blowfish/CBC/${padding.name}";

  @override
  final BlowfishInCBCModeEncrypt encryptor;

  @override
  final BlowfishInCBCModeDecrypt decryptor;

  const BlowfishInCBCMode._({
    required this.encryptor,
    required this.decryptor,
  });

  @override
  Uint8List get iv => encryptor.iv;

  /// Creates Blowfish cipher in CBC mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] 64-bit random initialization vector or salt
  /// - [padding] The padding scheme for the messages
  factory BlowfishInCBCMode(
    List<int> key, {
    List<int>? iv,
    Padding padding = Padding.pkcs7,
  }) {
    if (key.isEmpty || key.length > 56) {
      throw StateError('Key must be between 1 and 56 bytes');
    }
    iv ??= randomBytes(8);
    if (iv.length != 8) {
      throw StateError('IV must be exactly 8-bytes');
    }
    final iv8 = toUint8List(iv);
    final key8 = toUint8List(key);
    return BlowfishInCBCMode._(
      encryptor: BlowfishInCBCModeEncrypt(key8, iv8, padding),
      decryptor: BlowfishInCBCModeDecrypt(key8, iv8, padding),
    );
  }

  /// Padding scheme for the messages
  Padding get padding => encryptor.padding;
}
