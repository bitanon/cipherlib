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

class CipherlibBenchmark extends SyncBenchmark {
  final Uint8List key;
  CipherlibBenchmark(int size)
      : key = Uint8List.fromList(List.filled(size, 0x9f)),
        super('cipherlib', size);

  @override
  void run() {
    final key32 = Uint32List.view(key.buffer);
    cipher.AESCore.$expandDecryptionKey(key32);
  }
}

class PointyCastleBenchmark extends SyncBenchmark {
  final Uint8List key;
  PointyCastleBenchmark(int size)
      : key = Uint8List.fromList(List.filled(size, 0x9f)),
        super('PointyCastle', size);

  @override
  void run() {
    var instance = aes.AESEngine();
    instance.generateWorkingKey(false, pc.KeyParameter(key));
  }
}

class CryptographyBenchmark extends SyncBenchmark {
  final Uint8List key;
  CryptographyBenchmark(int size)
      : key = Uint8List.fromList(List.filled(size, 0x9f)),
        super('cryptography', size);

  @override
  void run() {
    aesExpandKeyForDecrypting(crypto.SecretKeyData(key));
  }
}

void main() async {
  for (int size in [16, 24, 32]) {
    print('---- AES-${size << 3} Keygen ----');
    await CipherlibBenchmark(size).measureDiff([
      PointyCastleBenchmark(size),
      CryptographyBenchmark(size),
    ]);
    print('');
  }
}
