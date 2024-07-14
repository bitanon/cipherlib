// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pointycastle/pointycastle.dart' as pc;

import 'base.dart';

Random random = Random();

class CipherlibBenchmark extends Benchmark {
  final Uint8List key;
  final Uint8List iv;

  CipherlibBenchmark(int size, int iter, int keySize)
      : key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(16, 0x87)),
        super('cipherlib', size, iter);

  @override
  void run() {
    AES(key).cbc(iv).encrypt(input);
  }
}

class PointyCastleBenchmark extends Benchmark {
  final Uint8List key;
  final Uint8List iv;

  PointyCastleBenchmark(int size, int iter, int keySize)
      : key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(16, 0x87)),
        super('PointyCastle', size, iter);

  @override
  void run() {
    var inp = Uint8List.fromList(input);
    var out = Uint8List(inp.length);
    var instance = pc.BlockCipher('AES/CBC');
    instance.init(
      true,
      pc.ParametersWithIV(pc.KeyParameter(key), iv),
    );
    for (int i = 0; i < inp.length; i += 16) {
      instance.processBlock(inp, i, out, i);
    }
  }
}

class CryptographyBenchmark extends AsyncBenchmark {
  final Uint8List key;
  final Uint8List iv;

  CryptographyBenchmark(int size, int iter, int keySize)
      : key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(16, 0x87)),
        super('cryptography', size, iter);

  @override
  Future<void> run() async {
    var instance = key.length == 16
        ? crypto.AesCbc.with128bits(
            macAlgorithm: crypto.MacAlgorithm.empty,
          )
        : key.length == 24
            ? crypto.AesCbc.with192bits(
                macAlgorithm: crypto.MacAlgorithm.empty,
              )
            : crypto.AesCbc.with256bits(
                macAlgorithm: crypto.MacAlgorithm.empty,
              );
    instance.encrypt(
      input,
      secretKey: crypto.SecretKey(key),
      nonce: iv,
    );
  }
}

void main() async {
  print('--------- AES/CBC ----------');
  final conditions = [
    [5 << 20, 10],
    [1 << 10, 5000],
    [16, 100000],
  ];
  for (var condition in conditions) {
    int size = condition[0];
    int iter = condition[1];
    print('---- message: ${formatSize(size)} | iterations: $iter ----');
    print('[AES-128]');
    await CipherlibBenchmark(size, iter, 16).measureDiff([
      PointyCastleBenchmark(size, iter, 16),
      CryptographyBenchmark(size, iter, 16),
    ]);
    print('[AES-192]');
    await CipherlibBenchmark(size, iter, 24).measureDiff([
      PointyCastleBenchmark(size, iter, 24),
      CryptographyBenchmark(size, iter, 24),
    ]);
    print('[AES-256]');
    await CipherlibBenchmark(size, iter, 32).measureDiff([
      PointyCastleBenchmark(size, iter, 32),
      CryptographyBenchmark(size, iter, 32),
    ]);
    print('');
  }
}
