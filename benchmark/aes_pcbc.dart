// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: unused_local_variable

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';

import '_base.dart';

class CipherlibBenchmark extends SyncBenchmark {
  final Uint8List input;
  final Uint8List key;
  final Uint8List iv;

  CipherlibBenchmark(int size, int keySize)
      : input = Uint8List.fromList(List.filled(size >> 1, 0x3f)),
        key = Uint8List.fromList(List.filled(keySize, 0x9f)),
        iv = Uint8List.fromList(List.filled(16, 0x87)),
        super('cipherlib', size);

  @override
  void run() {
    final aes = AES.pkcs7(key).pcbc(iv);
    final encrypted = aes.encrypt(input);
    final decrypted = aes.decrypt(encrypted);
  }
}

void main() async {
  print('--------- AES/PCBC ----------');
  for (int size in [1 << 20, 1 << 10, 1 << 5]) {
    print('---- message: ${formatSize(size)} ----');
    print('[AES-128]');
    await CipherlibBenchmark(size, 16).measureRate();
    print('[AES-192]');
    await CipherlibBenchmark(size, 24).measureRate();
    print('[AES-256]');
    await CipherlibBenchmark(size, 32).measureRate();
    print('');
  }
}
