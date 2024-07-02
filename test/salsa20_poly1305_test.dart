// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';

import 'package:cipherlib/cipherlib.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  test('encryption <-> decryption (convert)', () {
    var key = randomNumbers(32);
    var nonce = randomBytes(16);
    for (int j = 0; j < 100; ++j) {
      var text = randomNumbers(j);
      var mac = salsa20poly1305(
        text,
        key,
        nonce: nonce,
      );
      var cipher = salsa20(
        text,
        key,
        nonce,
      );
      var verified = salsa20poly1305(
        cipher,
        key,
        mac: mac.bytes,
        nonce: nonce,
      );
      expect(verified.hex(), equals(mac.hex()), reason: '[mac: $j]');
    }
  });
  test('encryption <-> decryption (stream)', () async {
    var key = randomNumbers(32);
    var nonce = randomBytes(8);
    for (int j = 0; j < 100; ++j) {
      var text = randomNumbers(j);
      var stream1 = Stream.fromIterable(text);
      var stream2 = Stream.fromIterable(text);
      var mac = salsa20poly1305Stream(
        stream1,
        key,
        nonce: nonce,
      ).then((x) => x.bytes);
      var cipher = salsa20Stream(
        stream2,
        key,
        nonce,
      );
      var verified = salsa20poly1305Stream(
        cipher,
        key,
        nonce: nonce,
        mac: mac,
      ).then((x) => x.bytes);
      expect(await verified, equals(await mac), reason: '[mac: $j]');
    }
  });
}
