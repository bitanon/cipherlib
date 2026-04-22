// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/src/utils/typed_data.dart';
import 'package:test/test.dart';

void main() {
  group('typed data conversion', () {
    test('toUint8List preserves TypedData offset and length', () {
      final backing = Uint8List.fromList(List.generate(32, (i) => i));
      final slice = Int8List.view(backing.buffer, 8, 8);

      final out = toUint8List(slice);

      expect(out, equals(Uint8List.fromList(backing.sublist(8, 16))));
      expect(out.length, equals(8));
    });

    test('AES/GCM accepts non-Uint8 typed slices correctly', () {
      final keyBytes = Uint8List.fromList(List.generate(16, (i) => i + 1));
      final ivBytes = Uint8List.fromList(List.generate(12, (i) => i + 20));
      final aadBytes = Uint8List.fromList(List.generate(7, (i) => i + 40));
      final msg = Uint8List.fromList(List.generate(31, (i) => i + 60));

      final keyBacking = Uint8List.fromList([
        200,
        201,
        ...keyBytes,
        202,
        203,
      ]);
      final ivBacking = Uint8List.fromList([101, 102, ...ivBytes, 103, 104]);
      final aadBacking = Uint8List.fromList([11, ...aadBytes, 12, 13]);

      final keyView = Int8List.view(keyBacking.buffer, 2, 16);
      final ivView = Int8List.view(ivBacking.buffer, 2, 12);
      final aadView = Int8List.view(aadBacking.buffer, 1, 7);

      final expected = AES(keyBytes).gcm(ivBytes, aad: aadBytes).encrypt(msg);
      final actual = AES(keyView).gcm(ivView, aad: aadView).encrypt(msg);

      expect(actual, equals(expected));
    });
  });
}
