// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  test('encryption <-> decryption (convert)', () {
    var key = randomNumbers(32);
    var nonce = randomBytes(16);
    for (int j = 0; j < 100; ++j) {
      var text = randomBytes(j);
      var res = salsa20poly1305(
        text,
        key,
        nonce: nonce,
      );
      var verified = salsa20poly1305(
        res.data,
        key,
        mac: res.tag.bytes,
        nonce: nonce,
      );
      expect(verified.data, equals(text), reason: '[text size: $j]');
    }
  });

  test('sign and verify', () {
    for (int i = 0; i < 100; ++i) {
      final key = randomBytes(32);
      final iv = randomBytes(16);
      final aad = randomBytes(key[0]);
      final message = randomBytes(i);
      final instance = Salsa20Poly1305(key: key, nonce: iv, aad: aad);
      final res = instance.sign(message);
      expect(instance.verify(res.data, res.tag.bytes), isTrue);
    }
  });

  test('decrypt with invalid mac', () {
    var key = Uint8List(32);
    var nonce = Uint8List(16);
    var sample = Uint8List(150);
    var aad = Uint8List(16);
    var res = salsa20poly1305(
      sample,
      key,
      nonce: nonce,
      aad: aad,
    );
    expect(
      () => salsa20poly1305(
        res.data,
        key,
        mac: Uint8List(16),
        nonce: nonce,
        aad: aad,
      ),
      throwsA((e) => e is AssertionError),
    );
  });
}
