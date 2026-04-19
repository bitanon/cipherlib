// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pointycastle/pointycastle.dart' as pc;

import '_base.dart';

Random random = Random();

class CipherlibBenchmark extends InputBenchmark {
  final Uint8List key;
  final Uint8List iv;

  CipherlibBenchmark(int size, int keySize)
      : key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(16, 0x87)),
        super('cipherlib', size);

  @override
  void run() {
    AES(key).ctr(iv).encrypt(input);
  }
}

class PointyCastleBenchmark extends InputBenchmark {
  final Uint8List key;
  final Uint8List iv;

  PointyCastleBenchmark(int size, int keySize)
      : key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(16, 0x87)),
        super('PointyCastle', size);

  @override
  void run() {
    var inp = Uint8List.fromList(input);
    var out = Uint8List(inp.length);
    var instance = pc.BlockCipher('AES/CTR');
    instance.init(
      true,
      pc.ParametersWithIV(pc.KeyParameter(key), iv),
    );
    for (int i = 0; i < inp.length; i += 16) {
      instance.processBlock(inp, i, out, i);
    }
  }
}

class CryptographyBenchmark extends AsyncInputBenchmark {
  final Uint8List key;
  final Uint8List iv;

  CryptographyBenchmark(int size, int keySize)
      : key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(16, 0x87)),
        super('cryptography', size);

  @override
  Future<void> run() async {
    var instance = key.length == 16
        ? crypto.AesCtr.with128bits(
            macAlgorithm: crypto.MacAlgorithm.empty,
          )
        : key.length == 24
            ? crypto.AesCtr.with192bits(
                macAlgorithm: crypto.MacAlgorithm.empty,
              )
            : crypto.AesCtr.with256bits(
                macAlgorithm: crypto.MacAlgorithm.empty,
              );
    await instance.encrypt(
      input,
      secretKey: crypto.SecretKey(key),
      nonce: iv,
    );
  }
}

void main() async {
  print('--------- AES/CTR ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 3]) {
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
