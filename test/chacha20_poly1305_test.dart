// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

import 'utils.dart';

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
      test('convert', () async {
        var res = chacha20poly1305(
          sample.codeUnits,
          key,
          nonce: nonce,
          aad: aad,
        );
        expect(cipher, equals(res.cipher));
        expect('1ae10b594f09e26a7e902ecbd0600691', equals(res.mac.hex()));
      });
      test('stream', () async {
        var stream = Stream.fromIterable(sample.codeUnits);
        var res = chacha20poly1305Stream(
          stream,
          key,
          nonce: nonce,
          aad: aad,
        );
        var mac = await res.mac;
        expect(cipher, equals(await res.cipher.toList()));
        expect('1ae10b594f09e26a7e902ecbd0600691', equals(mac.hex()));
      });
      test('convert without aad', () {
        var res = chacha20poly1305(
          sample.codeUnits,
          key,
          nonce: nonce,
        );
        expect(cipher, equals(res.cipher));
        expect('6a23a4681fd59456aea1d29f82477216', equals(res.mac.hex()));
      });
      test('verify and decrypt', () {
        var res = chacha20poly1305(
          sample.codeUnits,
          key,
          nonce: nonce,
          aad: aad,
        );
        var verified = chacha20poly1305(
          res.cipher,
          key,
          mac: res.mac.bytes,
          nonce: nonce,
          aad: aad,
        );
        expect(verified.cipher, equals(sample.codeUnits));
        expect('661e943467edb1963bfe9015190609f0', equals(verified.mac.hex()));
      });
      test('stream verify and decrypt', () async {
        var stream = Stream.fromIterable(sample.codeUnits);
        var res = chacha20poly1305Stream(
          stream,
          key,
          nonce: nonce,
          aad: aad,
        );
        var verified = chacha20poly1305Stream(
          res.cipher,
          key,
          mac: res.mac,
          nonce: nonce,
          aad: aad,
        );
        var finalMac = await verified.mac;
        expect(sample.codeUnits, equals(await verified.cipher.toList()));
        expect('1ae10b594f09e26a7e902ecbd0600691', equals(await res.mac));
        expect('661e943467edb1963bfe9015190609f0', equals(finalMac.hex()));
      });
    });
    test('encryption <-> decryption (convert)', () {
      var key = randomNumbers(32);
      for (int j = 0; j < 100; ++j) {
        var nonce = randomBytes(12);
        var text = randomNumbers(j);
        var plain = Uint8List.fromList(text);
        var res = chacha20poly1305(
          text,
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
      for (int j = 0; j < 100; ++j) {
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
        expect(plain, equals(bytes), reason: '[text: $j]');
      }
    });
  });
}
