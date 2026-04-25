// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:collection';
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

    test('toUint8List converts full TypedData view without slicing', () {
      final backing = Uint8List.fromList(List.generate(16, (i) => i + 3));
      final fullView = Int8List.view(backing.buffer);

      final out = toUint8List(fullView);

      expect(out, equals(backing));
      backing[0] = 77;
      expect(out[0], equals(77));
    });

    test('toUint8List handles plain List<int>', () {
      final out = toUint8List(<int>[9, 8, 7, 6]);
      expect(out, equals(Uint8List.fromList([9, 8, 7, 6])));
    });

    test('toUint8List clones a sliced Uint8List view', () {
      final backing = Uint8List.fromList(List.generate(10, (i) => i));
      final slice = Uint8List.view(backing.buffer, 2, 5);

      final out = toUint8List(slice);

      expect(out, equals(Uint8List.fromList([2, 3, 4, 5, 6])));
      slice[0] = 99;
      expect(out[0], equals(2));
    });

    test('toUint8List handles non-list iterables of type Set', () {
      final out = toUint8List({1, 2, 3, 4});
      expect(out, equals(Uint8List.fromList([1, 2, 3, 4])));
    });

    test('toUint8List handles non-list iterables of type Queue', () {
      final out = toUint8List(Queue<int>.from([1, 2, 3, 4]));
      expect(out, equals(Uint8List.fromList([1, 2, 3, 4])));
    });

    test('toUint8List returns same instance for full Uint8List buffer', () {
      final full = Uint8List.fromList(List.generate(8, (i) => i));
      final out = toUint8List(full);
      expect(identical(out, full), isTrue);
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

  group('validateLength', () {
    test('returns Uint8List when length is allowed', () {
      final out = validateLength('key', [1, 2, 3, 4], {4});
      expect(out, equals(Uint8List.fromList([1, 2, 3, 4])));
    });

    test('throws with single-size error message', () {
      expect(
        () => validateLength('nonce', [1, 2, 3], {12}),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message.toString(),
            'message',
            contains('length must be 12 bytes'),
          ),
        ),
      );
    });

    test('throws with sorted multi-size error message', () {
      expect(
        () => validateLength('key', [1, 2, 3], {32, 16, 24}),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message.toString(),
            'message',
            contains('length must be one of [16, 24, 32] bytes'),
          ),
        ),
      );
    });
  });
}
