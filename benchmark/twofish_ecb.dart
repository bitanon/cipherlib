// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: unused_local_variable

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:pointycastle/block/modes/ecb.dart';
import 'package:pointycastle/block/twofish.dart';
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
  Future<dynamic> run() async {
    final ecb = Twofish.noPadding(key).ecb();
    final encrypted = ecb.encrypt(input);
    return ecb.decrypt(encrypted);
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
  Future<dynamic> run() async {
    final params = pc.KeyParameter(key);

    // encrypt
    final encrypter = ECBBlockCipher(TwofishEngine())..init(true, params);
    final encrypted = Uint8List(input.length);
    for (int i = 0; i < input.length; i += 16) {
      encrypter.processBlock(input, i, encrypted, i);
    }

    // decrypt
    final decrypter = ECBBlockCipher(TwofishEngine())..init(false, params);
    final decrypted = Uint8List(encrypted.length);
    for (int i = 0; i < encrypted.length; i += 16) {
      decrypter.processBlock(encrypted, i, decrypted, i);
    }
    return decrypted;
  }
}

void main() async {
  print('--------- Twofish/ECB ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 5]) {
    print('---- message: ${formatSize(size)} ----');
    print('[Twofish-128]');
    await CipherlibBenchmark(size, 16).measureDiff([
      PointyCastleBenchmark(size, 16),
    ]);
    print('[Twofish-192]');
    await CipherlibBenchmark(size, 24).measureDiff([
      PointyCastleBenchmark(size, 24),
    ]);
    print('[Twofish-256]');
    await CipherlibBenchmark(size, 32).measureDiff([
      PointyCastleBenchmark(size, 32),
    ]);
    print('');
  }
}
