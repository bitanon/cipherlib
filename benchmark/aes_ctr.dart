// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: unused_local_variable

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pointycastle/pointycastle.dart' as pc;

import '_base.dart';

class CipherlibBenchmark extends AsyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List iv;

  CipherlibBenchmark(int size, int keySize)
      : input = Uint8List.fromList(List.filled(size >> 1, 0x3f)),
        key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(16, 0x87)),
        super('cipherlib', size);

  @override
  Future<void> run() async {
    final aes = AES(key).ctr(iv, 40);
    final encrypted = aes.encrypt(input);
    final decrypted = aes.decrypt(encrypted);
  }
}

class PointyCastleBenchmark extends AsyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List iv;

  PointyCastleBenchmark(int size, int keySize)
      : input = Uint8List.fromList(List.filled(size >> 1, 0x3f)),
        key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(16, 0x87)),
        super('PointyCastle', size);

  @override
  Future<void> run() async {
    final instance = pc.PaddedBlockCipher('AES/CTR/PKCS7');
    final params = pc.PaddedBlockCipherParameters(
      pc.ParametersWithIV(pc.KeyParameter(key), iv),
      null,
    );

    // encrypt
    instance.init(true, params);
    final encrypted = instance.process(input);

    // decrypt
    instance.init(false, params);
    final decrypted = instance.process(encrypted);
  }
}

class CryptographyBenchmark extends AsyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List iv;

  CryptographyBenchmark(int size, int keySize)
      : input = Uint8List.fromList(List.filled(size >> 1, 0x3f)),
        key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(16, 0x87)),
        super('cryptography', size);

  @override
  Future<void> run() async {
    final instance = crypto.Cryptography.instance.aesCtr(
      macAlgorithm: crypto.MacAlgorithm.empty,
      secretKeyLength: key.length,
      counterBits: 8,
    );
    final encrypted = await instance.encrypt(
      input,
      secretKey: crypto.SecretKey(key),
      nonce: iv,
    );
    final decrypted = await instance.decrypt(
      encrypted,
      secretKey: crypto.SecretKey(key),
    );
  }
}

void main() async {
  print('--------- AES/CTR ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 5]) {
    print('---- message: ${formatSize(size)} ----');
    print('[AES-128]');
    await CipherlibBenchmark(size, 16).measureDiff([
      PointyCastleBenchmark(size, 16),
      CryptographyBenchmark(size, 16),
    ]);
    print('[AES-192]');
    await CipherlibBenchmark(size, 24).measureDiff([
      PointyCastleBenchmark(size, 24),
      CryptographyBenchmark(size, 24),
    ]);
    print('[AES-256]');
    await CipherlibBenchmark(size, 32).measureDiff([
      PointyCastleBenchmark(size, 32),
      CryptographyBenchmark(size, 32),
    ]);
    print('');
  }
}
