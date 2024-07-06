// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/padding.dart';
import 'package:test/test.dart';

void main() {
  group('PaddingScheme.none', () {
    var block = List.filled(100, -1);
    test('pad <-> unpad', () {
      for (int s = 0; s < 100; ++s) {
        for (int i = 0; i <= s; ++i) {
          expect(Padding.none.pad(block, i, s), false,
              reason: 'pad | pos: $i, size: $s');
          var out = Padding.none.unpad(block, s);
          expect(out, equals(block.take(s)),
              reason: 'unpad | pos: $i, size: $s');
        }
      }
    });
  });

  group('PaddingScheme.zero', () {
    test('pad <-> unpad', () {
      for (int s = 0; s < 100; ++s) {
        for (int i = 0; i <= s; ++i) {
          var block = List.filled(100, -1);
          expect(Padding.zero.pad(block, i, s), true,
              reason: 'pad | pos: $i, size: $s');
          expect(block.skip(i).take(s - i), equals(List.filled(s - i, 0)),
              reason: 'pad-check | pos: $i, size: $s');
          var out = Padding.zero.unpad(block, s);
          expect(out, equals(block.take(i)),
              reason: 'unpad | pos: $i, size: $s');
        }
      }
    });
  });

  group('PaddingScheme.byte', () {
    test('throws StateError on empty block', () {
      expect(() => Padding.byte.pad(Uint8List(10), 10), throwsStateError);
      expect(() => Padding.byte.pad(Uint8List(0), 10), throwsStateError);
      expect(() => Padding.byte.pad(Uint8List(5), 0, 0), throwsStateError);
      expect(() => Padding.byte.pad(Uint8List(5), 3, 3), throwsStateError);
      expect(() => Padding.byte.pad(Uint8List(5), 10, 3), throwsStateError);
    });

    test('pad <-> unpad', () {
      for (int s = 1; s < 100; ++s) {
        for (int i = 0; i < s; ++i) {
          var block = List.filled(100, -1);
          expect(Padding.byte.pad(block, i, s), true,
              reason: 'pad | pos: $i, size: $s');
          var expected = List.filled(s - i, 0);
          expected[0] = 0x80;
          expect(block.skip(i).take(s - i), equals(expected),
              reason: 'pad-check | pos: $i, size: $s');
          var out = Padding.byte.unpad(block, s);
          expect(out, equals(block.take(i)),
              reason: 'unpad | pos: $i, size: $s');
        }
      }
    });
  });

  group('PaddingScheme.ansiX923', () {
    test('throws StateError on empty block', () {
      expect(() => Padding.ansiX923.pad(Uint8List(10), 10), throwsStateError);
      expect(() => Padding.ansiX923.pad(Uint8List(0), 10), throwsStateError);
      expect(() => Padding.ansiX923.pad(Uint8List(5), 0, 0), throwsStateError);
      expect(() => Padding.ansiX923.pad(Uint8List(5), 3, 3), throwsStateError);
      expect(() => Padding.ansiX923.pad(Uint8List(5), 10, 3), throwsStateError);
    });

    test('pad <-> unpad', () {
      for (int s = 1; s < 100; ++s) {
        for (int i = 0; i < s; ++i) {
          var block = List.filled(100, -1);
          expect(Padding.ansiX923.pad(block, i, s), true,
              reason: 'pad | pos: $i, size: $s');
          expect(
              block.skip(i).take(s - i - 1), equals(List.filled(s - i - 1, 0)),
              reason: 'pad-check-inner | pos: $i, size: $s');
          expect(block[s - 1], equals(s - i),
              reason: 'pad-check-last | pos: $i, size: $s');
          var out = Padding.ansiX923.unpad(block, s);
          expect(out, equals(block.take(i)),
              reason: 'unpad | pos: $i, size: $s');
        }
      }
    });
  });

  group('PaddingScheme.pkcs7', () {
    test('throws StateError on empty block', () {
      expect(() => Padding.pkcs7.pad(Uint8List(10), 10), throwsStateError);
      expect(() => Padding.pkcs7.pad(Uint8List(0), 10), throwsStateError);
      expect(() => Padding.pkcs7.pad(Uint8List(5), 0, 0), throwsStateError);
      expect(() => Padding.pkcs7.pad(Uint8List(5), 3, 3), throwsStateError);
      expect(() => Padding.pkcs7.pad(Uint8List(5), 10, 3), throwsStateError);
    });

    test('pad <-> unpad', () {
      for (int s = 1; s < 100; ++s) {
        for (int i = 0; i < s; ++i) {
          var block = List.filled(100, -1);
          expect(Padding.pkcs7.pad(block, i, s), true,
              reason: 'pad | pos: $i, size: $s');
          expect(block.skip(i).take(s - i), equals(List.filled(s - i, s - i)),
              reason: 'pad-check | pos: $i, size: $s');
          var out = Padding.pkcs7.unpad(block, s);
          expect(out, equals(block.take(i)),
              reason: 'unpad | pos: $i, size: $s');
        }
      }
    });
  });

  group('PaddingScheme.pkcs5', () {
    test('throws StateError on invalid block size', () {
      expect(() => Padding.pkcs5.pad(Uint8List(10), 2, 9), throwsStateError);
      expect(() => Padding.pkcs5.pad(Uint8List(10), 2, 7), throwsStateError);
      expect(() => Padding.pkcs5.pad(Uint8List(9), 2), throwsStateError);
      expect(() => Padding.pkcs5.pad(Uint8List(7), 2), throwsStateError);
    });

    test('throws StateError on empty block', () {
      expect(() => Padding.pkcs5.pad(Uint8List(8), 8), throwsStateError);
      expect(() => Padding.pkcs5.pad(Uint8List(0), 8), throwsStateError);
      expect(() => Padding.pkcs5.pad(Uint8List(10), 8, 8), throwsStateError);
      expect(() => Padding.pkcs5.pad(Uint8List(8), 10), throwsStateError);
    });

    test('pad <-> unpad', () {
      int s = 8;
      for (int i = 0; i < s; ++i) {
        var block = List.filled(100, -1);
        expect(Padding.pkcs5.pad(block, i, s), true,
            reason: 'pad | pos: $i, size: $s');
        expect(block.skip(i).take(s - i), equals(List.filled(s - i, s - i)),
            reason: 'pad-check | pos: $i, size: $s');
        var out = Padding.pkcs5.unpad(block, s);
        expect(out, equals(block.take(i)), reason: 'unpad | pos: $i, size: $s');
      }
    });
  });
}
