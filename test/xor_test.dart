// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

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
    test('encryption <-> decryption', () {
      for (int i = 1; i < 100; ++i) {
        var key = randomBytes(i);
        for (int j = 0; j < 100; ++j) {
          var text = randomBytes(j);
          var cipher = xor(text, key);
          var plain = xor(cipher, key);
          expect(text, equals(plain), reason: '[key: $i, text: $j]');
        }
      }
    });
  });
}
