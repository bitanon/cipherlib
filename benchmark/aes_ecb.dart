// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:pointycastle/pointycastle.dart' as pc;

import '_base.dart';

Random random = Random();

class CipherlibBenchmark extends InputBenchmark {
  final Uint8List key;

  CipherlibBenchmark(int size, int keySize)
      : key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        super('cipherlib', size);

  @override
  void run() {
    AES(key).ecb().encrypt(input);
  }
}

class PointyCastleBenchmark extends InputBenchmark {
  final Uint8List key;

  PointyCastleBenchmark(int size, int keySize)
      : key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        super('PointyCastle', size);

  @override
  void run() {
    var inp = Uint8List.fromList(input);
    var out = Uint8List(inp.length);
    var instance = pc.BlockCipher('AES/ECB');
    instance.init(true, pc.KeyParameter(key));
    for (int i = 0; i < inp.length; i += 16) {
      instance.processBlock(inp, i, out, i);
    }
  }
}

void main() async {
  print('--------- AES/ECB ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 3]) {
    print('---- message: ${formatSize(size)} ----');
    print('[AES-128]');
    await CipherlibBenchmark(size, 16).measureDiff([
      PointyCastleBenchmark(size, 16),
    ]);
    print('[AES-192]');
    await CipherlibBenchmark(size, 24).measureDiff([
      PointyCastleBenchmark(size, 24),
    ]);
    print('[AES-256]');
    await CipherlibBenchmark(size, 32).measureDiff([
      PointyCastleBenchmark(size, 32),
    ]);
    print('');
  }
}
