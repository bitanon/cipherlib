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

    test('can pad without the size parameter', () {
      var block = [-1, -1, -1];
      expect(Padding.zero.pad(block, 2), true);
      expect(block, equals([-1, -1, 0]));
    });

    test('can get pad length without size parameter', () {
      var block = [-1, -1, 0, 0, 0];
      expect(Padding.zero.getPadLength(block), 3);
    });

    test('can unpad without the size parameter', () {
      var block = [-1, -1, 0, 0, 0];
      expect(Padding.zero.unpad(block), equals([-1, -1]));
      expect(block, equals([-1, -1, 0, 0, 0]));
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

    test('can pad without the size parameter', () {
      var block = [-1, -1, -1];
      expect(Padding.byte.pad(block, 2), true);
      expect(block, equals([-1, -1, 0x80]));
    });

    test('can get pad length without size parameter', () {
      var block = [-1, -1, 0x80, 0, 0];
      expect(Padding.byte.getPadLength(block), 3);
    });

    test('can unpad without the size parameter', () {
      var block = [-1, -1, 0x80, 0, 0];
      expect(Padding.byte.unpad(block), equals([-1, -1]));
      expect(block, equals([-1, -1, 0x80, 0, 0]));
    });

    test('throws when it contains invalid byte', () {
      var block = [-1, -1, 0x80, 1, 0];
      expect(() => Padding.byte.getPadLength(block), throwsStateError);
    });

    test('throws when no sign byte is present', () {
      var block = [0, 0, 0, 0];
      expect(() => Padding.byte.getPadLength(block), throwsStateError);
    });
  });

  group('PaddingScheme.ansi', () {
    test('throws StateError on empty block', () {
      expect(() => Padding.ansi.pad(Uint8List(10), 10), throwsStateError);
      expect(() => Padding.ansi.pad(Uint8List(0), 10), throwsStateError);
      expect(() => Padding.ansi.pad(Uint8List(5), 0, 0), throwsStateError);
      expect(() => Padding.ansi.pad(Uint8List(5), 3, 3), throwsStateError);
      expect(() => Padding.ansi.pad(Uint8List(5), 10, 3), throwsStateError);
    });

    test('pad <-> unpad', () {
      for (int s = 1; s < 100; ++s) {
        for (int i = 0; i < s; ++i) {
          var block = List.filled(100, -1);
          expect(Padding.ansi.pad(block, i, s), true,
              reason: 'pad | pos: $i, size: $s');
          expect(
              block.skip(i).take(s - i - 1), equals(List.filled(s - i - 1, 0)),
              reason: 'pad-check-inner | pos: $i, size: $s');
          expect(block[s - 1], equals(s - i),
              reason: 'pad-check-last | pos: $i, size: $s');
          var out = Padding.ansi.unpad(block, s);
          expect(out, equals(block.take(i)),
              reason: 'unpad | pos: $i, size: $s');
        }
      }
    });

    test('can pad without the size parameter', () {
      var block = [-1, -1, -1, -1];
      expect(Padding.ansi.pad(block, 2), true);
      expect(block, equals([-1, -1, 0, 2]));
    });

    test('can get pad length without size parameter', () {
      var block = [-1, -1, 0, 0, 3];
      expect(Padding.ansi.getPadLength(block), 3);
    });

    test('can unpad without the size parameter', () {
      var block = [-1, -1, 0, 0, 3];
      expect(Padding.ansi.unpad(block), equals([-1, -1]));
      expect(block, equals([-1, -1, 0, 0, 3]));
    });

    test('throws when padding count is invalid', () {
      var block = [-1, -1, 0, 0, 10];
      expect(() => Padding.ansi.getPadLength(block), throwsStateError);
    });

    test('throws when padding bytes are not valid', () {
      var block = [-1, -1, -1, 0, 3];
      expect(() => Padding.ansi.getPadLength(block), throwsStateError);
    });

    test('max padding size limit is 255', () {
      var block = Uint8List(260);
      expect(() => Padding.ansi.pad(block, 0), throwsStateError);
      expect(() => Padding.ansi.pad(block, 1), throwsStateError);
      expect(() => Padding.ansi.pad(block, 2), throwsStateError);
      expect(() => Padding.ansi.pad(block, 3), throwsStateError);
      expect(() => Padding.ansi.pad(block, 4), throwsStateError);
      Padding.ansi.pad(block, 5);
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

    test('can pad without the size parameter', () {
      var block = [-1, -1, -1, -1];
      expect(Padding.pkcs7.pad(block, 2), true);
      expect(block, equals([-1, -1, 2, 2]));
    });

    test('can get pad length without size parameter', () {
      var block = [-1, -1, 3, 3, 3];
      expect(Padding.pkcs7.getPadLength(block), 3);
    });

    test('can unpad without the size parameter', () {
      var block = [-1, -1, 3, 3, 3];
      expect(Padding.pkcs7.unpad(block), equals([-1, -1]));
      expect(block, equals([-1, -1, 3, 3, 3]));
    });

    test('max padding size limit is 255', () {
      var block = Uint8List(260);
      expect(() => Padding.pkcs7.pad(block, 0), throwsStateError);
      expect(() => Padding.pkcs7.pad(block, 1), throwsStateError);
      expect(() => Padding.pkcs7.pad(block, 2), throwsStateError);
      expect(() => Padding.pkcs7.pad(block, 3), throwsStateError);
      expect(() => Padding.pkcs7.pad(block, 4), throwsStateError);
      Padding.pkcs7.pad(block, 5);
    });

    test('throws when sign byte is not valid', () {
      var block = [-1, -1, 10, 10, 10];
      expect(() => Padding.pkcs7.getPadLength(block), throwsStateError);
    });

    test('throws when sign byte is not sequential', () {
      var block = [-1, -1, 0, 3, 3];
      expect(() => Padding.pkcs7.getPadLength(block), throwsStateError);
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
