// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/src/xor.dart';
import 'package:test/test.dart';

void main() {
  group('validation', () {
    test('name', () {
      expect(XOR(Uint8List(1)).name, 'XOR');
    });
    test('rejects empty key', () {
      expect(() => xor([], []), throwsArgumentError);
      expect(() => xor([1], []), throwsArgumentError);
    });
    test('allows empty message', () {
      expect(xor([], [1]), equals(<int>[]));
    });
  });

  group("known inputs", () {
    test("all zeros", () {
      final key = Uint8List.fromList([0x00]);
      final plain = Uint8List.fromList([0x00, 0x00]);
      final cipher = xor(plain, key);
      expect(cipher, equals([0x00, 0x00]));
    });
    test("all ones", () {
      final key = Uint8List.fromList([0xff]);
      final plain = Uint8List.fromList([0xff, 0xff]);
      final cipher = xor(plain, key);
      expect(cipher, equals([0x00, 0x00]));
    });
    test("both zeros and ones", () {
      final key = Uint8List.fromList([0x00, 0xff]);
      final plain = Uint8List.fromList([0x00, 0xff]);
      final cipher = xor(plain, key);
      final back = xor(cipher, key);
      expect(back, equals(plain));
    });
    test('golden vector', () {
      final key = 'key'.codeUnits;
      final plain = 'plaintext'.codeUnits;
      final expected = fromHex('1b0918020b0d0e1d0d');
      expect(xor(plain, key), equals(expected));
      expect(xor(expected, key), equals(plain));
    });
  });

  group("critical inputs", () {
    test("empty key", () {
      final key = Uint8List.fromList([]);
      final plain = Uint8List.fromList([0x00, 0x00]);
      expect(() => xor(plain, key), throwsArgumentError);
    });
    test("empty message", () {
      final key = Uint8List.fromList([0x00]);
      final plain = Uint8List.fromList([]);
      expect(xor(plain, key), equals([]));
    });
    test("key longer than message", () {
      final key = Uint8List.fromList([0x00, 0x00]);
      final plain = Uint8List.fromList([0x00]);
      expect(xor(plain, key), equals([0x00]));
    });
    test("message longer than key", () {
      final key = Uint8List.fromList([0x00]);
      final plain = Uint8List.fromList([0x00, 0x00]);
      expect(xor(plain, key), equals([0x00, 0x00]));
    });
    test('does not mutate input', () {
      final key = Uint8List.fromList([0x55]);
      final buf = Uint8List.fromList([0x00, 0xff]);
      final ref = buf;
      XOR(key).convert(buf);
      expect(identical(ref, buf), isTrue);
      expect(buf, equals([0x00, 0xff]));
    });
  });
}
