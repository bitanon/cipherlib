// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/src/chacha20_poly1305.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

void main() {
  group('Test ChaCha20/Poly1305 cipher', () {
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
      var tag = fromHex("1ae10b594f09e26a7e902ecbd0600691");
      test('convert', () {
        var res = chacha20poly1305(
          sample.codeUnits,
          key,
          nonce: nonce,
          aad: aad,
        );
        expect(cipher, equals(res.cipher));
        expect(tag, equals(res.tag));
      });
      test('verify', () {
        var res = chacha20poly1305(
          sample.codeUnits,
          key,
          nonce: nonce,
          aad: aad,
        );
        var verified = chacha20poly1305(
          res.cipher,
          key,
          tag: res.tag.bytes,
          nonce: nonce,
          aad: aad,
        );
        expect(sample.codeUnits, equals(verified.cipher));
      });
    });
  });
}
