// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/src/xor.dart' as cipher;

import '_base.dart';

Random random = Random();

class CipherlibBenchmark extends InputBenchmark {
  final Uint8List key;

  CipherlibBenchmark(int size)
      : key = Uint8List.fromList(List.filled(100, 0x9f)),
        super('cipherlib', size);

  @override
  void run() {
    cipher.XOR(key).convert(input);
  }
}

class CipherlibStreamBenchmark extends AsyncInputBenchmark {
  final Uint8List key;

  CipherlibStreamBenchmark(int size)
      : key = Uint8List.fromList(List.filled(100, 0x9f)),
        super('cipherlib', size);

  @override
  Future<void> run() async {
    await cipher.XOR(key).stream(inputStream).drain();
  }
}

void main() async {
  print('--------- XOR ----------');
  for (var size in [1 << 20, 1 << 10, 1 << 3]) {
    print('---- message: ${formatSize(size)} ----');
    await CipherlibBenchmark(size).measureRate();
    await CipherlibStreamBenchmark(size).measureRate();
    print('');
  }
}
