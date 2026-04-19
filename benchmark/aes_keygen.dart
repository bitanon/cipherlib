// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart' as cipher;
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:cryptography/src/dart/aes_impl.dart';
import 'package:pointycastle/block/aes.dart' as aes;
import 'package:pointycastle/pointycastle.dart' as pc;

import '_base.dart';

Random random = Random();

class CipherlibBenchmark extends InputBenchmark {
  late final Uint8List key;
  CipherlibBenchmark(int size) : super('cipherlib', size) {
    key = Uint8List.fromList(input);
  }

  @override
  void run() {
    cipher.AESCore.$expandDecryptionKey(Uint32List.view(key.buffer));
  }
}

class PointyCastleBenchmark extends InputBenchmark {
  late final Uint8List key;
  PointyCastleBenchmark(int size) : super('PointyCastle', size) {
    key = Uint8List.fromList(input);
  }

  @override
  void run() {
    var instance = aes.AESEngine();
    instance.generateWorkingKey(false, pc.KeyParameter(key));
  }
}

class CryptographyBenchmark extends InputBenchmark {
  late final Uint8List key;
  CryptographyBenchmark(int size) : super('cryptography', size) {
    key = Uint8List.fromList(input);
  }

  @override
  void run() {
    aesExpandKeyForDecrypting(crypto.SecretKeyData(key));
  }
}

void main() async {
  print('--------- AES/ECB ----------');
  for (int size in [16, 24, 32]) {
    print('---- keysize: $size ----');
    await CipherlibBenchmark(size).measureDiff([
      PointyCastleBenchmark(size),
      CryptographyBenchmark(size),
    ]);
    print('');
  }
}
