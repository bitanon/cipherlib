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
          expect(PaddingScheme.none.pad(block, i, s), false,
              reason: 'pad | pos: $i, size: $s');
          var out = PaddingScheme.none.unpad(block, s);
          expect(block.take(s), equals(out),
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
          expect(PaddingScheme.zero.pad(block, i, s), true,
              reason: 'pad | pos: $i, size: $s');
          expect(block.skip(i).take(s - i), equals(List.filled(s - i, 0)),
              reason: 'pad-check | pos: $i, size: $s');
          var out = PaddingScheme.zero.unpad(block, s);
          expect(block.take(i), equals(out),
              reason: 'unpad | pos: $i, size: $s');
        }
      }
    });
  });

  group('PaddingScheme.byte', () {
    test('throws StateError on empty block', () {
      expect(() => PaddingScheme.byte.pad(Uint8List(10), 10), throwsStateError);
      expect(() => PaddingScheme.byte.pad(Uint8List(0), 10), throwsStateError);
      expect(
          () => PaddingScheme.byte.pad(Uint8List(5), 0, 0), throwsStateError);
      expect(
          () => PaddingScheme.byte.pad(Uint8List(5), 3, 3), throwsStateError);
      expect(
          () => PaddingScheme.byte.pad(Uint8List(5), 10, 3), throwsStateError);
    });

    test('pad <-> unpad', () {
      for (int s = 1; s < 100; ++s) {
        for (int i = 0; i < s; ++i) {
          var block = List.filled(100, -1);
          expect(PaddingScheme.byte.pad(block, i, s), true,
              reason: 'pad | pos: $i, size: $s');
          var expected = List.filled(s - i, 0);
          expected[0] = 0x80;
          expect(block.skip(i).take(s - i), equals(expected),
              reason: 'pad-check | pos: $i, size: $s');
          var out = PaddingScheme.byte.unpad(block, s);
          expect(block.take(i), equals(out),
              reason: 'unpad | pos: $i, size: $s');
        }
      }
    });
  });

  group('PaddingScheme.ansiX923', () {
    test('throws StateError on empty block', () {
      expect(() => PaddingScheme.ansiX923.pad(Uint8List(10), 10),
          throwsStateError);
      expect(
          () => PaddingScheme.ansiX923.pad(Uint8List(0), 10), throwsStateError);
      expect(() => PaddingScheme.ansiX923.pad(Uint8List(5), 0, 0),
          throwsStateError);
      expect(() => PaddingScheme.ansiX923.pad(Uint8List(5), 3, 3),
          throwsStateError);
      expect(() => PaddingScheme.ansiX923.pad(Uint8List(5), 10, 3),
          throwsStateError);
    });

    test('pad <-> unpad', () {
      for (int s = 1; s < 100; ++s) {
        for (int i = 0; i < s; ++i) {
          var block = List.filled(100, -1);
          expect(PaddingScheme.ansiX923.pad(block, i, s), true,
              reason: 'pad | pos: $i, size: $s');
          expect(
              block.skip(i).take(s - i - 1), equals(List.filled(s - i - 1, 0)),
              reason: 'pad-check-inner | pos: $i, size: $s');
          expect(block[s - 1], equals(s - i),
              reason: 'pad-check-last | pos: $i, size: $s');
          var out = PaddingScheme.ansiX923.unpad(block, s);
          expect(block.take(i), equals(out),
              reason: 'unpad | pos: $i, size: $s');
        }
      }
    });
  });

  group('PaddingScheme.pkcs7', () {
    test('throws StateError on empty block', () {
      expect(
          () => PaddingScheme.pkcs7.pad(Uint8List(10), 10), throwsStateError);
      expect(() => PaddingScheme.pkcs7.pad(Uint8List(0), 10), throwsStateError);
      expect(
          () => PaddingScheme.pkcs7.pad(Uint8List(5), 0, 0), throwsStateError);
      expect(
          () => PaddingScheme.pkcs7.pad(Uint8List(5), 3, 3), throwsStateError);
      expect(
          () => PaddingScheme.pkcs7.pad(Uint8List(5), 10, 3), throwsStateError);
    });

    test('pad <-> unpad', () {
      for (int s = 1; s < 100; ++s) {
        for (int i = 0; i < s; ++i) {
          var block = List.filled(100, -1);
          expect(PaddingScheme.pkcs7.pad(block, i, s), true,
              reason: 'pad | pos: $i, size: $s');
          expect(block.skip(i).take(s - i), equals(List.filled(s - i, s - i)),
              reason: 'pad-check | pos: $i, size: $s');
          var out = PaddingScheme.pkcs7.unpad(block, s);
          expect(block.take(i), equals(out),
              reason: 'unpad | pos: $i, size: $s');
        }
      }
    });
  });

  group('PaddingScheme.pkcs5', () {
    test('throws StateError on invalid block size', () {
      expect(
          () => PaddingScheme.pkcs5.pad(Uint8List(10), 2, 9), throwsStateError);
      expect(
          () => PaddingScheme.pkcs5.pad(Uint8List(10), 2, 7), throwsStateError);
      expect(() => PaddingScheme.pkcs5.pad(Uint8List(9), 2), throwsStateError);
      expect(() => PaddingScheme.pkcs5.pad(Uint8List(7), 2), throwsStateError);
    });

    test('throws StateError on empty block', () {
      expect(() => PaddingScheme.pkcs5.pad(Uint8List(8), 8), throwsStateError);
      expect(() => PaddingScheme.pkcs5.pad(Uint8List(0), 8), throwsStateError);
      expect(
          () => PaddingScheme.pkcs5.pad(Uint8List(10), 8, 8), throwsStateError);
      expect(() => PaddingScheme.pkcs5.pad(Uint8List(8), 10), throwsStateError);
    });

    test('pad <-> unpad', () {
      int s = 8;
      for (int i = 0; i < s; ++i) {
        var block = List.filled(100, -1);
        expect(PaddingScheme.pkcs5.pad(block, i, s), true,
            reason: 'pad | pos: $i, size: $s');
        expect(block.skip(i).take(s - i), equals(List.filled(s - i, s - i)),
            reason: 'pad-check | pos: $i, size: $s');
        var out = PaddingScheme.pkcs5.unpad(block, s);
        expect(block.take(i), equals(out), reason: 'unpad | pos: $i, size: $s');
      }
    });
  });
}
