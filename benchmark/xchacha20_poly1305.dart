// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';

import '_base.dart';

Random random = Random();

class CipherlibBenchmark extends AsyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List nonce;

  CipherlibBenchmark(int size)
      : input = Uint8List.fromList(List.filled(size, 0x3f)),
        key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(32, 0x2f)),
        super('cipherlib', size);

  @override
  Future<void> run() async {
    XChaCha20(key, nonce).poly1305().sign(input);
  }
}

void main() async {
  print('--------- ChaCha20/Poly1305 ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 5]) {
    print('---- message: ${formatSize(size)} ----');
    await CipherlibBenchmark(size).measureRate();
    print('');
  }
}
