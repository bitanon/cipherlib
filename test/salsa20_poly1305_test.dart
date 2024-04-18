// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  group('Test Salsa20/Poly1305 cipher', () {
    test('encryption <-> decryption (convert)', () {
      var key = randomNumbers(32);
      for (int j = 0; j < 100; j += 5) {
        var nonce = randomBytes(12);
        var text = randomNumbers(j);
        var plain = Uint8List.fromList(text);
        var res = chacha20poly1305(
          plain,
          key,
          nonce: nonce,
        );
        var verified = chacha20poly1305(
          res.cipher,
          key,
          mac: res.mac.bytes,
          nonce: nonce,
        );
        expect(plain, equals(verified.cipher), reason: '[text: $j]');
      }
    });
    test('encryption <-> decryption (stream)', () async {
      var key = randomNumbers(32);
      for (int j = 0; j < 500; j += 50) {
        var nonce = randomBytes(12);
        var text = randomNumbers(j);
        var bytes = Uint8List.fromList(text);
        var stream = Stream.fromIterable(text);
        var res = chacha20poly1305Stream(
          stream,
          key,
          nonce: nonce,
        );
        var verified = chacha20poly1305Stream(
          res.cipher,
          key,
          nonce: nonce,
          mac: res.mac,
        );
        var plain = await verified.cipher.toList();
        expect(bytes, equals(plain), reason: '[ text: $j]');
      }
    });
  });
}
