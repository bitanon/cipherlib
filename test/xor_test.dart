// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  group('Test XOR cipher', () {
    test('empty key', () {
      expect(() => xor([], []), throwsArgumentError);
    });
    test('empty message', () {
      expect(xor([], [1]), equals([]));
    });
    test('encryption <-> decryption (convert)', () {
      for (int i = 1; i < 100; ++i) {
        var key = randomNumbers(i);
        for (int j = 0; j < 100; ++j) {
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
        for (int j = 0; j < 100; ++j) {
          var text = randomNumbers(j);
          var bytes = Uint8List.fromList(text);
          var stream = Stream.fromIterable(text);
          var cipherStream = xorPipe(stream, key);
          var plainStream = xorPipe(cipherStream, key);
          var plain = await plainStream.toList();
          expect(bytes, equals(plain), reason: '[key: $i, text: $j]');
        }
      }
    });
    test('single instance', () {
      for (int i = 1; i < 20; ++i) {
        var key = randomNumbers(i);
        var instance = XOR(key);
        for (int j = 0; j < 100; ++j) {
          var text = randomNumbers(j);
          var bytes = Uint8List.fromList(text);
          var cipher = instance.convert(bytes);
          var plain = instance.convert(cipher);
          expect(bytes, equals(plain), reason: '[key: $i, text: $j]');
        }
      }
    });
  });
}
