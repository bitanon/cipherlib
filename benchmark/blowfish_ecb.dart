// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: unused_local_variable

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:pointycastle/block/blowfish.dart';
import 'package:pointycastle/block/modes/ecb.dart';
import 'package:pointycastle/pointycastle.dart' as pc;

import '_base.dart';

class CipherlibBenchmark extends AsyncBenchmark {
  final Uint8List input;
  final Uint8List key;

  CipherlibBenchmark(int size, int keySize)
      : input = Uint8List.fromList(List.filled(size >> 1, 0x3f)),
        key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        super('cipherlib', size);

  @override
  Future<void> run() async {
    final ecb = Blowfish.noPadding(key).ecb();
    final encrypted = ecb.encrypt(input);
    final decrypted = ecb.decrypt(encrypted);
  }
}

class PointyCastleBenchmark extends AsyncBenchmark {
  final Uint8List input;
  final Uint8List key;

  PointyCastleBenchmark(int size, int keySize)
      : input = Uint8List.fromList(List.filled(size >> 1, 0x3f)),
        key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        super('PointyCastle', size);

  @override
  Future<void> run() async {
    final params = pc.KeyParameter(key);

    // encrypt
    final encrypter = ECBBlockCipher(BlowfishEngine())..init(true, params);
    final encrypted = Uint8List(input.length);
    for (int i = 0; i < input.length; i += 8) {
      encrypter.processBlock(input, i, encrypted, i);
    }

    // decrypt
    final decrypter = ECBBlockCipher(BlowfishEngine())..init(false, params);
    final decrypted = Uint8List(encrypted.length);
    for (int i = 0; i < encrypted.length; i += 8) {
      decrypter.processBlock(encrypted, i, decrypted, i);
    }
  }
}

void main() async {
  print('--------- Blowfish/ECB ----------');
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
