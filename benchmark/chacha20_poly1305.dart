// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pointycastle/pointycastle.dart' as pc;

import '_base.dart';

Random random = Random();

class CipherlibBenchmark extends AsyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List nonce;

  CipherlibBenchmark(int size)
      : input = Uint8List.fromList(List.filled(size, 0x3f)),
        key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(12, 0x2f)),
        super('cipherlib', size);

  @override
  Future<void> run() async {
    ChaCha20Poly1305(key, nonce: nonce).sign(input);
  }
}

class CryptographyBenchmark extends AsyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List nonce;

  CryptographyBenchmark(int size)
      : input = Uint8List.fromList(List.filled(size, 0x3f)),
        key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(12, 0x2f)),
        super('cryptography', size);

  @override
  Future<void> run() async {
    await crypto.Chacha20.poly1305Aead().encrypt(
      input,
      secretKey: crypto.SecretKeyData(key),
      nonce: nonce,
    );
  }
}

class PointyCastleBenchmark extends AsyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List nonce;

  PointyCastleBenchmark(int size)
      : input = Uint8List.fromList(List.filled(size, 0x3f)),
        key = Uint8List.fromList(List.filled(32, 0x9f)),
        nonce = Uint8List.fromList(List.filled(12, 0x2f)),
        super('PointyCastle', size);

  @override
  Future<void> run() async {
    final instance = pc.AEADCipher('ChaCha20-Poly1305');
    final parameters = pc.ParametersWithIV(pc.KeyParameter(key), nonce);
    instance.init(true, parameters);
    final output = Uint8List(input.length);
    instance.processBytes(input, 0, size, output, 0);
  }
}

void main() async {
  print('--------- ChaCha20/Poly1305 ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 5]) {
    print('---- message: ${formatSize(size)} ----');
    await CipherlibBenchmark(size).measureDiff([
      CryptographyBenchmark(size),
      PointyCastleBenchmark(size),
    ]);
    print('');
  }
}
