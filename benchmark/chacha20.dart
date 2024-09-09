// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart' as cipher;
import 'package:pointycastle/pointycastle.dart' as pc;

import 'base.dart';

Random random = Random();

class CipherlibBenchmark extends Benchmark {
  final Uint8List key;
  final Uint8List nonce;

  CipherlibBenchmark(int size, int iter)
      : key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(12, 0x2f)),
        super('cipherlib', size, iter);

  @override
  void run() {
    cipher.chacha20(input, key, nonce: nonce);
  }
}

class PointyCastleBenchmark extends Benchmark {
  final Uint8List key;
  final Uint8List nonce;

  PointyCastleBenchmark(int size, int iter)
      : key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(12, 0x2f)),
        super('PointyCastle', size, iter);

  @override
  void run() {
    var instance = pc.StreamCipher('ChaCha7539/20');
    instance.init(
      true,
      pc.ParametersWithIV(pc.KeyParameter(key), nonce),
    );
    var inp = Uint8List.fromList(input);
    var out = Uint8List(input.length);
    instance.processBytes(inp, 0, size, out, 0);
  }
}

class CipherlibStreamBenchmark extends AsyncBenchmark {
  final Uint8List key;
  final Uint8List nonce;

  CipherlibStreamBenchmark(int size, int iter)
      : key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(12, 0x2f)),
        super('cipherlib', size, iter);

  @override
  Future<void> run() async {
    await cipher.chacha20Stream(inputStream, key, nonce: nonce).drain();
  }
}

void main() async {
  print('--------- ChaCha20 ----------');
  final conditions = [
    [5 << 20, 10],
    [1 << 10, 5000],
    [16, 100000],
  ];
  for (var condition in conditions) {
    int size = condition[0];
    int iter = condition[1];
    print('---- message: ${formatSize(size)} | iterations: $iter ----');
    await CipherlibBenchmark(size, iter).measureDiff([
      PointyCastleBenchmark(size, iter),
    ]);
    print('---- stream: ${formatSize(size)} | iterations: $iter ----');
    await CipherlibStreamBenchmark(size, iter).measureRate();
    print('');
  }
}
