// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';

import '_base.dart';

Random random = Random();

class CipherlibBenchmark extends InputBenchmark {
  final Uint8List key;
  final Uint8List iv;

  CipherlibBenchmark(int size, int keySize)
      : key = Uint8List.fromList(List.filled(2 * keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(16, 0x87)),
        super('cipherlib', size);

  @override
  void run() {
    AES(key).xts(iv).encrypt(input);
  }
}

void main() async {
  print('--------- AES/XTS ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 3]) {
    print('---- message: ${formatSize(size)} ----');
    print('[AES-128]');
    CipherlibBenchmark(size, 16).measureRate();
    print('[AES-192]');
    CipherlibBenchmark(size, 24).measureRate();
    print('[AES-256]');
    CipherlibBenchmark(size, 32).measureRate();
    print('');
  }
}
