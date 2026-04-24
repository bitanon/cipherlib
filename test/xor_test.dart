// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
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

  group('stream support', () {
    test('bind preserves key position across chunks', () async {
      final cipher = XOR([1, 2, 3]);
      final stream = Stream<List<int>>.fromIterable([
        [10, 11],
        [12, 13, 14],
      ]);

      final chunks = await cipher.bind(stream).toList();

      expect(chunks, hasLength(2));
      expect(chunks[0], equals([11, 9]));
      expect(chunks[1], equals([15, 12, 12]));
    });

    test('bind wraps key correctly within a large single chunk', () async {
      final cipher = XOR([1, 2, 3]);
      final stream = Stream<List<int>>.fromIterable([
        [10, 11, 12, 13, 14],
      ]);

      final chunks = await cipher.bind(stream).toList();

      expect(chunks, hasLength(1));
      expect(chunks[0], equals([11, 9, 15, 12, 12]));
    });

    test('stream transforms byte stream with custom chunk size', () async {
      final cipher = XOR([1, 2, 3]);
      final input = Stream<int>.fromIterable([10, 11, 12, 13, 14]);

      final output = await cipher.stream(input, 2).toList();

      expect(output, equals([11, 9, 15, 12, 12]));
    });

    test('cast is unsupported for StreamCipher', () {
      final cipher = XOR([1]);
      expect(
        () => cipher.cast<List<int>, Uint8List>(),
        throwsA(
          isA<UnsupportedError>().having(
            (e) => e.message,
            'message',
            'StreamCipher does not allow casting',
          ),
        ),
      );
    });
  });
}
