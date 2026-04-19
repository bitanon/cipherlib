// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart' as cipher;

import '_base.dart';

Random random = Random();

class CipherlibBenchmark extends InputBenchmark {
  final Uint8List key;
  final Uint8List nonce;

  CipherlibBenchmark(int size)
      : key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(16, 0x2f)),
        super('cipherlib', size);

  @override
  void run() {
    cipher.Salsa20Poly1305(key, nonce: nonce).convert(input);
  }
}

void main() {
  print('--------- Salsa20/Poly1305 ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 3]) {
    print('---- message: ${formatSize(size)} ----');
    CipherlibBenchmark(size).measureRate();
    print('');
  }
}
