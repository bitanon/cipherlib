// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart' as cipher;

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
    cipher.chacha20(input, key);
  }
}

class CipherlibStreamBenchmark extends Benchmark {
  final Uint8List key;
  final Uint8List nonce;

  CipherlibStreamBenchmark(int size, int iter)
      : key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(12, 0x2f)),
        super('cipherlib', size, iter);

  @override
  void run() {
    cipher.chacha20Pipe(inputStream, key);
  }
}

void main() {
  print('--------- ChaCha20 ----------');
  final conditions = [
    [5 << 20, 10],
    [1 << 10, 5000],
    [10, 100000],
  ];
  for (var condition in conditions) {
    int size = condition[0];
    int iter = condition[1];
    print('---- message: ${formatSize(size)} | iterations: $iter ----');
    CipherlibBenchmark(size, iter).showDiff([]);
    print('---- stream: ${formatSize(size)} | iterations: $iter ----');
    CipherlibStreamBenchmark(size, iter).showDiff([]);
    print('');
  }
}
