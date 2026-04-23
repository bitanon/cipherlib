// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:pointycastle/pointycastle.dart' as pc;

import '_base.dart';

class CipherlibBenchmark extends SyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List nonce;

  CipherlibBenchmark(int size)
      : input = Uint8List.fromList(List.filled(size, 0x3f)),
        key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(8, 0x2f)),
        super('cipherlib', size);

  @override
  void run() {
    Salsa20(key, nonce).convert(input);
  }
}

class PointyCastleBenchmark extends SyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List nonce;

  PointyCastleBenchmark(int size)
      : input = Uint8List.fromList(List.filled(size, 0x3f)),
        key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(8, 0x2f)),
        super('PointyCastle', size);

  @override
  void run() {
    final instance = pc.StreamCipher('Salsa20');
    final parameters = pc.ParametersWithIV(pc.KeyParameter(key), nonce);
    instance.init(true, parameters);
    instance.process(input);
  }
}

void main() async {
  print('--------- Salsa20 ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 5]) {
    print('---- message: ${formatSize(size)} ----');
    await CipherlibBenchmark(size).measureDiff([
      PointyCastleBenchmark(size),
    ]);
    print('');
  }
}
