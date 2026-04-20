// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';

import '_base.dart';

class CipherlibBenchmark extends SyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List nonce;

  CipherlibBenchmark(int size)
      : input = Uint8List.fromList(List.filled(size, 0x3f)),
        key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(32, 0x2f)),
        super('cipherlib', size);

  @override
  void run() {
    XChaCha20(key, nonce).convert(input);
  }
}

class CipherlibStreamBenchmark extends AsyncBenchmark {
  final Stream<int> input;
  final Uint8List key;
  final Uint8List nonce;

  CipherlibStreamBenchmark(int size)
      : input = Stream.fromIterable(List.filled(size, 0x3f)),
        key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(32, 0x2f)),
        super('cipherlib', size);

  @override
  Future<void> run() async {
    await XChaCha20(key, nonce).stream(input).drain();
  }
}

void main() async {
  print('--------- ChaCha20 ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 5]) {
    print('---- message: ${formatSize(size)} ----');
    await CipherlibBenchmark(size).measureRate();
    await CipherlibStreamBenchmark(size).measureRate();
    print('');
  }
}
