// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

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
        res.message,
        key,
        mac: res.mac.bytes,
        nonce: nonce,
      );
      expect(verified.message, equals(text), reason: '[text: $j]');
      expect(verified.mac.hex(), equals(res.mac.hex()), reason: '[mac: $j]');
    }
  });
}
