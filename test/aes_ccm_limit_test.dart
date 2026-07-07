// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: library_annotations

@TestOn('vm')

import 'dart:ffi';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:test/test.dart';

void main() {
  group('CCM limits', () {
    test('additional authenticated data must be less than 2^32 bytes', () {
      final key = Uint8List(16);
      final nonce = Uint8List(13);
      // A typed data view reporting a length of 2^32 without any allocation.
      // The length guard throws before a single byte of it is ever read.
      final hugeAad = Pointer<Uint8>.fromAddress(8).asTypedList(0x100000000);
      final core = AESInCCMModeCipherCore(key, nonce, hugeAad, 16);
      expect(() => core.encrypt([1, 2, 3]), throwsStateError);
    });
  });
}
