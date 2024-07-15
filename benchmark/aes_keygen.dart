// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aes/_core.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:cryptography/src/dart/aes_impl.dart';
import 'package:pointycastle/block/aes.dart' as aes;
import 'package:pointycastle/pointycastle.dart' as pc;

import 'base.dart';

Random random = Random();

class CipherlibBenchmark extends Benchmark {
  late final Uint8List key = Uint8List.fromList(input);

  CipherlibBenchmark(int size, int iter) : super('cipherlib', size, iter);

  @override
  void run() {
    AESCore.$expandDecryptionKey(Uint32List.view(key.buffer));
  }
}

class PointyCastleBenchmark extends Benchmark {
  late final Uint8List key = Uint8List.fromList(input);

  PointyCastleBenchmark(int size, int iter) : super('PointyCastle', size, iter);

  @override
  void run() {
    var instance = aes.AESEngine();
    instance.generateWorkingKey(false, pc.KeyParameter(key));
  }
}

class CryptographyBenchmark extends Benchmark {
  late final Uint8List key = Uint8List.fromList(input);

  CryptographyBenchmark(int size, int iter) : super('cryptography', size, iter);

  @override
  void run() {
    aesExpandKeyForDecrypting(crypto.SecretKeyData(key));
  }
}

void main() async {
  print('--------- AES/ECB ----------');
  final conditions = [
    [16, 100],
    [24, 100],
    [32, 100],
  ];
  for (var condition in conditions) {
    int size = condition[0];
    int iter = condition[1];
    print('---- keysize: $size iterations: $iter ----');
    await CipherlibBenchmark(size, iter).measureDiff([
      PointyCastleBenchmark(size, iter),
      CryptographyBenchmark(size, iter),
    ]);
    print('');
  }
}
