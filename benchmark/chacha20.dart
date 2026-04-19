// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart' as cipher;
import 'package:pointycastle/pointycastle.dart' as pc;

import '_base.dart';

Random random = Random();

class CipherlibBenchmark extends InputBenchmark {
  final Uint8List key;
  final Uint8List nonce;

  CipherlibBenchmark(int size)
      : key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(12, 0x2f)),
        super('cipherlib', size);

  @override
  void run() {
    cipher.ChaCha20(key, nonce).convert(input);
  }
}

class PointyCastleBenchmark extends InputBenchmark {
  final Uint8List key;
  final Uint8List nonce;

  PointyCastleBenchmark(int size)
      : key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(12, 0x2f)),
        super('PointyCastle', size);

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

class CipherlibStreamBenchmark extends AsyncInputBenchmark {
  final Uint8List key;
  final Uint8List nonce;

  CipherlibStreamBenchmark(int size)
      : key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(12, 0x2f)),
        super('cipherlib', size);

  @override
  Future<void> run() async {
    await cipher.ChaCha20(key, nonce).stream(inputStream).drain();
  }
}

void main() async {
  print('--------- ChaCha20 ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 3]) {
    print('---- message: ${formatSize(size)} ----');
    await CipherlibBenchmark(size).measureDiff([
      PointyCastleBenchmark(size),
    ]);
    print('---- stream: ${formatSize(size)} ----');
    await CipherlibStreamBenchmark(size).measureRate();
    print('');
  }
}
