// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aes/_core.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:cryptography/src/dart/aes_impl.dart';
import 'package:pointycastle/block/aes.dart' as aes;
import 'package:pointycastle/pointycastle.dart' as pc;

import 'base.dart';

Random random = Random();

class CipherlibBenchmark extends Benchmark {
  final Uint8List key;

  CipherlibBenchmark(int size, int iter, int keySize)
      : key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        super('cipherlib', size, iter);

  @override
  void run() {
    var key32 = Uint32List.view(key.buffer);
    AESCore.$expandEncryptionKey(key32);
  }
}

class PointyCastleBenchmark extends Benchmark {
  final Uint8List key;

  PointyCastleBenchmark(int size, int iter, int keySize)
      : key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        super('PointyCastle', size, iter);

  @override
  void run() {
    var instance = aes.AESEngine();
    instance.generateWorkingKey(true, pc.KeyParameter(key));
  }
}

class CryptographyBenchmark extends Benchmark {
  final Uint8List key;

  CryptographyBenchmark(int size, int iter, int keySize)
      : key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        super('cryptography', size, iter);

  @override
  void run() {
    aesExpandKeyForEncrypting(crypto.SecretKeyData(key));
  }
}

void main() async {
  print('--------- AES/ECB ----------');
  final conditions = [
    [5 << 20, 10],
    [1 << 10, 5000],
    [16, 100000],
  ];
  for (var condition in conditions) {
    int size = condition[0];
    int iter = condition[1];
    print('---- message: ${formatSize(size)} | iterations: $iter ----');
    await CipherlibBenchmark(size, iter, 16).measureDiff([
      PointyCastleBenchmark(size, iter, 16),
      CryptographyBenchmark(size, iter, 16),
    ]);
    await CipherlibBenchmark(size, iter, 24).measureDiff([
      PointyCastleBenchmark(size, iter, 24),
      CryptographyBenchmark(size, iter, 24),
    ]);
    await CipherlibBenchmark(size, iter, 32).measureDiff([
      PointyCastleBenchmark(size, iter, 32),
      CryptographyBenchmark(size, iter, 32),
    ]);
    print('');
  }
}
