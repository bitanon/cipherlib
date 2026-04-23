// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';

import '_base.dart';

class CipherlibBenchmark extends SyncBenchmark {
  final Uint8List input;
  final Uint8List key;

  CipherlibBenchmark(int size)
      : input = Uint8List.fromList(List.filled(size, 0x3f)),
        key = Uint8List.fromList(List.filled(100, 0x9f)),
        super('cipherlib', size);

  @override
  void run() {
    XOR(key).convert(input);
  }
}

// class CipherlibStreamBenchmark extends AsyncBenchmark {
//   final Stream<int> input;
//   final Uint8List key;

//   CipherlibStreamBenchmark(int size)
//       : input = Stream.fromIterable(List.filled(size, 0x3f)),
//         key = Uint8List.fromList(List.filled(100, 0x9f)),
//         super('cipherlib', size);

//   @override
//   Future<void> run() async {
//     await XOR(key).stream(input).drain();
//   }
// }

void main() async {
  print('--------- XOR ----------');
  for (var size in [1 << 20, 1 << 10, 1 << 5]) {
    print('---- message: ${formatSize(size)} ----');
    await CipherlibBenchmark(size).measureRate();
    // await CipherlibStreamBenchmark(size).measureRate();
    print('');
  }
}
