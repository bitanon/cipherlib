// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';

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
    AES(key).pcbc(iv).encrypt(input);
  }
}

void main() async {
  print('--------- AES/PCBC ----------');
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
    CipherlibBenchmark(size, iter, 16).measureRate();
    print('[AES-192]');
    CipherlibBenchmark(size, iter, 24).measureRate();
    print('[AES-256]');
    CipherlibBenchmark(size, iter, 32).measureRate();
    print('');
  }
}
