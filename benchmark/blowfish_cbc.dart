// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: unused_local_variable

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:pointycastle/block/blowfish.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/pointycastle.dart' as pc;

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
    final cbc = Blowfish.noPadding(key).cbc(iv);
    final encrypted = cbc.encrypt(input);
    return cbc.decrypt(encrypted);
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
    final encrypter = CBCBlockCipher(BlowfishEngine())..init(true, params);
    final encrypted = Uint8List(input.length);
    for (int i = 0; i < input.length; i += 8) {
      encrypter.processBlock(input, i, encrypted, i);
    }

    // decrypt
    final decrypter = CBCBlockCipher(BlowfishEngine())..init(false, params);
    final decrypted = Uint8List(encrypted.length);
    for (int i = 0; i < encrypted.length; i += 8) {
      decrypter.processBlock(encrypted, i, decrypted, i);
    }
    return decrypted;
  }
}

void main() async {
  print('--------- Blowfish/CBC ----------');
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
