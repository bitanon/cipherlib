// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';

import 'package:cipherlib/cipherlib.dart' as cipher;

import 'base.dart';

Random random = Random();

class CipherlibBenchmark extends SymmetricKeyBenchmark {
  CipherlibBenchmark(int size, int key, int iter)
      : super('cipherlib', size, key, iter);

  @override
  void run() {
    cipher.xor(input, key);
  }
}

class CipherlibStreamBenchmark extends SymmetricKeyBenchmark {
  CipherlibStreamBenchmark(int size, int key, int iter)
      : super('cipherlib', size, key, iter);

  @override
  void run() {
    cipher.xorPipe(inputStream, key);
  }
}

void main() {
  print('--------- XOR ----------');
  final conditions = [
    [5 << 20, 10],
    [1 << 10, 5000],
    [10, 100000],
  ];
  for (var condition in conditions) {
    int size = condition[0];
    int iter = condition[1];
    print('---- message: ${formatSize(size)} | iterations: $iter ----');
    CipherlibBenchmark(size, 10, iter).showDiff([
      CipherlibBenchmark(size, 1 << 10, iter),
      CipherlibBenchmark(size, 1 << 20, iter),
    ]);
    print('---- stream: ${formatSize(size)} | iterations: $iter ----');
    CipherlibStreamBenchmark(size, 10, iter).showDiff([
      CipherlibStreamBenchmark(size, 1 << 10, iter),
      CipherlibStreamBenchmark(size, 1 << 20, iter),
    ]);
    print('');
  }
}
