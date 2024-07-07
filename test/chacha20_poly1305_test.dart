// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  group('RFC 8439 example', () {
    var key = fromHex(
      "808182838485868788898a8b8c8d8e8f"
      "909192939495969798999a9b9c9d9e9f",
    );
    var nonce = fromHex("070000004041424344454647");
    var sample = "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    var aad = fromHex("50515253c0c1c2c3c4c5c6c7");
    var cipher = fromHex(
      "d31a8d34648e60db7b86afbc53ef7ec2"
      "a4aded51296e08fea9e2b5a736ee62d6"
      "3dbea45e8ca9671282fafb69da92728b"
      "1a71de0a9e060b2905d6a5b67ecd3b36"
      "92ddbd7f2d778b8c9803aee328091b58"
      "fab324e4fad675945585808b4831d7bc"
      "3ff4def08e4b7a9de576d26586cec64b"
      "6116",
    );
    test('convert', () async {
      var res = chacha20poly1305(
        sample.codeUnits,
        key,
        nonce: nonce,
        aad: aad,
      );
      expect(res.tag.hex(), equals('1ae10b594f09e26a7e902ecbd0600691'));
    });
    test('convert without aad', () {
      var res = chacha20poly1305(
        sample.codeUnits,
        key,
        nonce: nonce,
      );
      expect(res.tag.hex(), equals('6a23a4681fd59456aea1d29f82477216'));
    });
    test('verify and decrypt', () {
      var res = chacha20poly1305(
        sample.codeUnits,
        key,
        nonce: nonce,
        aad: aad,
      );
      var verified = chacha20poly1305(
        cipher,
        key,
        mac: res.tag.bytes,
        nonce: nonce,
        aad: aad,
      );
      expect(verified.data, equals(sample.codeUnits));
    });
  });

  test('encryption <-> decryption (convert)', () {
    var key = randomNumbers(32);
    var nonce = randomBytes(12);
    for (int j = 0; j < 100; ++j) {
      var text = randomBytes(j);
      var res = chacha20poly1305(
        text,
        key,
        nonce: nonce,
      );
      var verified = chacha20poly1305(
        res.data,
        key,
        mac: res.tag.bytes,
        nonce: nonce,
      );
      expect(verified.data, equals(text), reason: '[text size: $j]');
    }
  });
}
