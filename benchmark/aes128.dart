// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aes/aes_encrypt.dart';

import 'base.dart';

Random random = Random();

class CipherlibBenchmark extends Benchmark {
  final Uint8List key;

  CipherlibBenchmark(int size, int iter)
      : key = Uint8List.fromList(List.filled(16, 0x9f)),
        super('cipherlib', size, iter);

  @override
  void run() {
    AESEncrypt(key).convert(input);
  }
}

class CipherlibStreamBenchmark extends AsyncBenchmark {
  final Uint8List key;

  CipherlibStreamBenchmark(int size, int iter)
      : key = Uint8List.fromList(List.filled(16, 0x9f)),
        super('cipherlib', size, iter);

  @override
  Future<void> run() async {
    await AESEncrypt(key).stream(inputStream).drain();
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
    CipherlibBenchmark(size, iter).measureRate();
    print('---- stream: ${formatSize(size)} | iterations: $iter ----');
    await CipherlibStreamBenchmark(size, iter).measureRate();
    print('');
  }
}
