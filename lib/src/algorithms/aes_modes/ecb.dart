// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async' show Stream;
import 'dart:typed_data';

import '../../core/aes.dart';
import '../../core/cipher.dart';
import '../../utils/typed_data.dart';
import '../padding.dart';

/// Provides encryption for AES cipher in ECB mode.
class AESInECBModeEncrypt extends StreamCipher {
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
  Uint8List convert(List<int> message) {
    int i, j, n, m, pos;
    n = message.length;
    m = n + 16 - (n & 15);

    final output = Uint8List(m);
    final block32 = Uint32List(4); // 128-bit
    final key32 = Uint32List.view(key.buffer);
    final block = Uint8List.view(block32.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xkey32 = AESCore.$expandEncryptionKey(key32);

    // process 16-byte blocks
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

      AESCore.$encryptLE(block32, xkey32);

      j = i >>> 2;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];
      output32[j + 2] = block32[2];
      output32[j + 3] = block32[3];
    }

    // process last block
    for (pos = 0; i + pos < n; ++pos) {
      block[pos] = message[i + pos];
    }
    if (padding.pad(block, pos)) {
      AESCore.$encryptLE(block32, xkey32);

      j = i >>> 2;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];
      output32[j + 2] = block32[2];
      output32[j + 3] = block32[3];

      i += 16;
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

    final pending = Uint8List(16);
    final block32 = Uint32List(4); // 128-bit
    final key32 = Uint32List.view(key.buffer);
    final block = Uint8List.view(block32.buffer);
    final pending32 = Uint32List.view(pending.buffer);
    final xkey32 = AESCore.$expandEncryptionKey(key32);

    await for (final chunk in stream) {
      for (i = 0; i < chunk.length; ++i) {
        pending[pos++] = chunk[i];
        if (pos == 16) {
          block32[0] = pending32[0];
          block32[1] = pending32[1];
          block32[2] = pending32[2];
          block32[3] = pending32[3];
          AESCore.$encryptLE(block32, xkey32);
          yield block.sublist(0);
          pos = 0;
        }
      }
    }

    for (j = 0; j < pos; ++j) {
      block[j] = pending[j];
    }
    if (padding.pad(block, pos)) {
      AESCore.$encryptLE(block32, xkey32);
      yield block.sublist(0);
      pos = 0;
    }

    if (pos != 0) {
      throw StateError('Invalid input size');
    }
  }
}

/// Provides decryption for AES cipher in ECB mode.
class AESInECBModeDecrypt extends StreamCipher {
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
  Uint8List convert(List<int> message) {
    int i, j, n;
    n = message.length;

    final output = Uint8List(n);
    final block32 = Uint32List(4); // 128-bit
    final key32 = Uint32List.view(key.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xkey32 = AESCore.$expandDecryptionKey(key32);

    if ((n & 15) != 0) {
      throw StateError('Invalid input size');
    }

    // process 16-byte blocks
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

      AESCore.$decryptLE(block32, xkey32);

      j = i >>> 2;
      output32[j + 0] = block32[0];
      output32[j + 1] = block32[1];
      output32[j + 2] = block32[2];
      output32[j + 3] = block32[3];
    }

    return padding.unpad(output);
  }

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) async* {
    int i;
    int pos = 0;
    Uint8List? lastBlock;

    final pending = Uint8List(16);
    final block32 = Uint32List(4); // 128-bit
    final key32 = Uint32List.view(key.buffer);
    final xkey32 = AESCore.$expandDecryptionKey(key32);
    final pending32 = Uint32List.view(pending.buffer);

    await for (final chunk in stream) {
      for (i = 0; i < chunk.length; ++i) {
        pending[pos++] = chunk[i];
        if (pos == 16) {
          if (lastBlock != null) {
            yield lastBlock;
          }
          block32[0] = pending32[0];
          block32[1] = pending32[1];
          block32[2] = pending32[2];
          block32[3] = pending32[3];
          AESCore.$decryptLE(block32, xkey32);
          lastBlock = Uint8List.view(block32.buffer).sublist(0);
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

/// Provides encryption and decryption for AES cipher in ECB mode.
class AESInECBMode extends StreamCipherPair {
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
    if (key.length != 16 && key.length != 24 && key.length != 32) {
      throw StateError('Key must be 16, 24, or 32 bytes');
    }
    final key8 = toUint8List(key);
    return AESInECBMode._(
      encryptor: AESInECBModeEncrypt(key8, padding),
      decryptor: AESInECBModeDecrypt(key8, padding),
    );
  }

  /// Padding scheme for the messages
  Padding get padding => encryptor.padding;
}
