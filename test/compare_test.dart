// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

@Tags(['skip-js'])

import 'package:cipherlib/cipherlib.dart' as cipher;
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  group('ChaCha20/Poly1305 cipher', () {
    test('compare with cryptography', () async {
      var key = randomBytes(32);
      for (int j = 0; j < 300; ++j) {
        var nonce = randomBytes(12);
        var text = randomBytes(j);
        var aad = randomBytes(key[0]);
        var my = cipher.chacha20poly1305(
          text,
          key,
          nonce: nonce,
          aad: aad,
        );
        var other = await crypto.Chacha20.poly1305Aead().encrypt(
          text,
          secretKey: crypto.SecretKey(key),
          nonce: nonce,
          aad: aad,
        );
        expect(other.cipherText, equals(my.data),
            reason: '[text: $j, aad: ${key[0]}]');
        expect(other.mac.bytes, equals(my.tag.bytes),
            reason: '[text: $j, aad: ${key[0]}]]');
      }
    });
  });
}
