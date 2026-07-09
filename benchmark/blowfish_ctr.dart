// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: unused_local_variable

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:pointycastle/block/blowfish.dart';
import 'package:pointycastle/pointycastle.dart' as pc;
import 'package:pointycastle/stream/ctr.dart';

import '_base.dart';

class CipherlibBenchmark extends AsyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List iv;

  CipherlibBenchmark(int size, int keySize)
      : input = Uint8List.fromList(List.filled(size >> 1, 0x3f)),
        key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(8, 0x87)),
        super('cipherlib', size);

  @override
  Future<dynamic> run() async {
    final ctr = Blowfish.noPadding(key).ctr(iv);
    final encrypted = ctr.encrypt(input);
    return ctr.decrypt(encrypted);
  }
}

class PointyCastleBenchmark extends AsyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List iv;

  PointyCastleBenchmark(int size, int keySize)
      : input = Uint8List.fromList(List.filled(size >> 1, 0x3f)),
        key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(8, 0x87)),
        super('PointyCastle', size);

  @override
  Future<dynamic> run() async {
    final params = pc.ParametersWithIV(pc.KeyParameter(key), iv);

    // encrypt
    final encrypter = CTRStreamCipher(BlowfishEngine())..init(true, params);
    final encrypted = encrypter.process(input);

    // decrypt
    final decrypter = CTRStreamCipher(BlowfishEngine())..init(false, params);
    return decrypter.process(encrypted);
  }
}

void main() async {
  print('--------- Blowfish/CTR ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 5]) {
    print('---- message: ${formatSize(size)} ----');
    print('[Blowfish-128]');
    await CipherlibBenchmark(size, 16).measureDiff([
      PointyCastleBenchmark(size, 16),
    ]);
    print('[Blowfish-256]');
    await CipherlibBenchmark(size, 32).measureDiff([
      PointyCastleBenchmark(size, 32),
    ]);
    print('[Blowfish-448]');
    await CipherlibBenchmark(size, 56).measureDiff([
      PointyCastleBenchmark(size, 56),
    ]);
    print('');
  }
}
