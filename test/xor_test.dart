// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/src/xor.dart';
import 'package:test/test.dart';

import 'utils.dart';

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

  group('correctness', () {
    test('encryption <-> decryption (convert)', () {
      for (int i = 1; i < 100; i += 10) {
        var key = randomNumbers(i);
        for (int j = 0; j < 100; j += 5) {
          var text = randomNumbers(j);
          var bytes = Uint8List.fromList(text);
          var cipher = xor(text, key);
          var plain = xor(cipher, key);
          expect(bytes, equals(plain), reason: '[key: $i, text: $j]');
        }
      }
    });
    test('encryption <-> decryption (stream)', () async {
      for (int i = 1; i < 10; ++i) {
        var key = randomNumbers(i);
        for (int j = 0; j < 100; j += 8) {
          var text = randomNumbers(j);
          var bytes = Uint8List.fromList(text);
          var stream = Stream.fromIterable(text);
          var cipherStream = XOR(key).stream(stream);
          var plainStream = XOR(key).stream(cipherStream);
          var plain = await plainStream.toList();
          expect(bytes, equals(plain), reason: '[key: $i, text: $j]');
        }
      }
    });

    test('bind starts key over for each chunk', () async {
      final key = Uint8List.fromList([1, 2, 3]);
      final plain = Uint8List.fromList([5, 5, 5, 5]);
      final whole = XOR(key).convert(plain);
      final merged = await XOR(key)
          .bind(Stream.fromIterable([plain.sublist(0, 2), plain.sublist(2)]))
          .fold<Uint8List>(
            Uint8List(0),
            (a, b) => Uint8List.fromList([...a, ...b]),
          );
      expect(merged, isNot(equals(whole)));
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
