// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async' show Stream;
import 'dart:typed_data';

import '../../core/cipher.dart';
import '../../core/twofish.dart';
import '../../utils/typed_data.dart';
import '../padding.dart';

/// Provides encryption for Twofish cipher in ECB mode.
class TwofishInECBModeEncrypt extends StreamCipher {
  @override
  String get name => "Twofish#encrypt/ECB/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Padding scheme for the input message
  final Padding padding;

  const TwofishInECBModeEncrypt(
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
    final block = Uint8List.view(block32.buffer);
    final output32 = Uint32List.view(output.buffer);
    final xkey32 = TwofishCore.$expandKey(key);

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

      TwofishCore.$encrypt(block32, xkey32);

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
      TwofishCore.$encrypt(block32, xkey32);

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
    final block = Uint8List.view(block32.buffer);
    final pending32 = Uint32List.view(pending.buffer);
    final xkey32 = TwofishCore.$expandKey(key);

    await for (final chunk in stream) {
      for (i = 0; i < chunk.length; ++i) {
        pending[pos++] = chunk[i];
        if (pos == 16) {
          block32[0] = pending32[0];
          block32[1] = pending32[1];
          block32[2] = pending32[2];
          block32[3] = pending32[3];
          TwofishCore.$encrypt(block32, xkey32);
          yield block.sublist(0);
          pos = 0;
        }
      }
    }

    for (j = 0; j < pos; ++j) {
      block[j] = pending[j];
    }
    if (padding.pad(block, pos)) {
      TwofishCore.$encrypt(block32, xkey32);
      yield block.sublist(0);
      pos = 0;
    }

    if (pos != 0) {
      throw StateError('Invalid input size');
    }
  }
}

/// Provides decryption for Twofish cipher in ECB mode.
class TwofishInECBModeDecrypt extends StreamCipher {
  @override
  String get name => "Twofish#decrypt/ECB/${padding.name}";

  /// Key for the cipher
  final Uint8List key;

  /// Padding scheme for the output message
  final Padding padding;

  const TwofishInECBModeDecrypt(
    this.key, [
    this.padding = Padding.pkcs7,
  ]);

  @override
  Uint8List convert(List<int> message) {
    int i, j, n;
    n = message.length;

    final output = Uint8List(n);
    final block32 = Uint32List(4); // 128-bit
    final output32 = Uint32List.view(output.buffer);
    final xkey32 = TwofishCore.$expandKey(key);

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

      TwofishCore.$decrypt(block32, xkey32);

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
    final pending32 = Uint32List.view(pending.buffer);
    final xkey32 = TwofishCore.$expandKey(key);

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
          TwofishCore.$decrypt(block32, xkey32);
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

/// Provides encryption and decryption for Twofish cipher in ECB mode.
class TwofishInECBMode extends StreamCipherPair {
  @override
  String get name => "Twofish/ECB/${padding.name}";

  @override
  final TwofishInECBModeEncrypt encryptor;

  @override
  final TwofishInECBModeDecrypt decryptor;

  const TwofishInECBMode._({
    required this.encryptor,
    required this.decryptor,
  });

  /// Creates Twofish cipher in ECB mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [padding] The padding scheme for the messages
  factory TwofishInECBMode(
    List<int> key, [
    Padding padding = Padding.pkcs7,
  ]) {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
      throw StateError('Key must be 16, 24, or 32 bytes');
    }
    final key8 = toUint8List(key);
    return TwofishInECBMode._(
      encryptor: TwofishInECBModeEncrypt(key8, padding),
      decryptor: TwofishInECBModeDecrypt(key8, padding),
    );
  }

  /// Padding scheme for the messages
  Padding get padding => encryptor.padding;
}
