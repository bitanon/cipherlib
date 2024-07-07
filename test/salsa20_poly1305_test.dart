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
        res.data,
        key,
        mac: res.tag.bytes,
        nonce: nonce,
      );
      expect(verified.data, equals(text), reason: '[text size: $j]');
    }
  });
}
