// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:hashlib/random.dart';
import 'package:test/test.dart';

void main() {
  group('known inputs', () {
    group('RFC 8439', () {
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
      test('encrypt, verify tag, and open', () {
        var tag = fromHex('1ae10b594f09e26a7e902ecbd0600691');
        var res = chacha20poly1305(
          sample.codeUnits,
          key,
          nonce: nonce,
          aad: aad,
        );
        expect(res.data, equals(cipher));
        expect(res.mac.bytes, equals(tag));
        expect(res.verify(tag), true);
        var verified = chacha20poly1305(
          res.data,
          key,
          mac: res.mac.bytes,
          nonce: nonce,
          aad: aad,
        );
        expect(verified.data, equals(sample.codeUnits));
      });
      test('without aad', () {
        var res = chacha20poly1305(
          sample.codeUnits,
          key,
          nonce: nonce,
        );
        expect(res.mac.hex(), equals('6a23a4681fd59456aea1d29f82477216'));
      });
    });
  });

  group('correctness', () {
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
          mac: res.mac.bytes,
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
        final instance = ChaCha20(key, iv).poly1305(aad);
        final res = instance.sign(message);
        expect(instance.verify(res.data, res.mac.bytes), isTrue);
      }
    });

    test('reset iv', () {
      var x = ChaCha20(Uint8List(32)).poly1305();
      var iv = [...x.iv];
      var key1 = [...x.cipher.key];
      var key2 = [...x.algo.keypair];
      var tag1 = x.sign(const [1, 2, 3, 4]).mac.bytes;
      x.resetIV();
      expect(iv, isNot(equals(x.iv)));
      expect(key1, equals(x.cipher.key));
      expect(key2, isNot(equals(x.algo.keypair)));
      var tag2 = x.sign(const [1, 2, 3, 4]).mac.bytes;
      expect(tag1, isNot(equals(tag2)));
    });

    group('RFC 8439 streaming API', () {
      var key = fromHex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f",
      );
      var nonce = fromHex("070000004041424344454647");
      var sample = "Ladies and Gentlemen of the class of '99: "
              "If I could offer you only one tip for the future, "
              "sunscreen would be it."
          .codeUnits;
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
      var algo = ChaCha20(key, nonce).poly1305(aad);

      test('defines name correctly', () {
        expect(algo.name, "ChaCha20/Poly1305");
      });
      test('accepts integer stream', () async {
        var stream = Stream.fromIterable(sample);
        var output = await algo.stream(stream).toList();
        expect(output, equals(cipher));
      });
    });
  });

  group('critical inputs', () {
    test('decrypt with invalid mac', () {
      var key = fromHex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f",
      );
      var nonce = fromHex("070000004041424344454647");
      var sample = "Ladies and Gentlemen of the class of '99: "
          "If I could offer you only one tip for the future, "
          "sunscreen would be it.";
      var aad = fromHex("50515253c0c1c2c3c4c5c6c7");
      var res = chacha20poly1305(
        sample.codeUnits,
        key,
        nonce: nonce,
        aad: aad,
      );
      expect(
        () => chacha20poly1305(
          res.data,
          key,
          mac: Uint8List(16),
          nonce: nonce,
          aad: aad,
        ),
        throwsA(isA<StateError>()),
      );
    });
  });
}
