// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  group('Test ChaCha20 cipher', () {
    test('empty key', () {
      expect(() => chacha20([], []), throwsArgumentError);
    });
    test('empty message', () {
      var key = randomNumbers(32);
      var nonce = randomBytes(12);
      expect(chacha20([], key, nonce), equals([]));
    });
    test('without nonce', () {
      var key = randomNumbers(32);
      var text = randomBytes(100);
      var cipher = chacha20(text, key);
      var plain = chacha20(cipher, key);
      expect(text, equals(plain));
    });
    test('specific round', () {
      int round = 113;
      var key = randomNumbers(32);
      var nonce = randomNumbers(12);
      var text = randomBytes(100);
      var instance = ChaCha20(counter: round, key: key, nonce: nonce);
      var cipher = instance.convert(text);
      var plain = instance.convert(cipher);
      expect(text, equals(plain));
    });
    test('RFC 8439', () {
      var key = fromHex(
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
      var nonce = fromHex("000000000000004a00000000");
      var sample = "Ladies and Gentlemen of the class of '99: "
          "If I could offer you only one tip for the future, "
          "sunscreen would be it.";
      var output = fromHex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d",
      );
      var cipher = chacha20(sample.codeUnits, key, nonce);
      expect(output, equals(cipher));
    });
    test('encryption <-> decryption', () {
      for (int i = 1; i < 100; ++i) {
        var key = randomNumbers(32);
        var nonce = randomBytes(12);
        for (int j = 0; j < 100; ++j) {
          var text = randomNumbers(j);
          var bytes = Uint8List.fromList(text);
          var cipher = chacha20(text, key, nonce);
          var plain = chacha20(cipher, key, nonce);
          expect(bytes, equals(plain), reason: '[key: $i, text: $j]');
        }
      }
    });
    test('encryption <-> decryption (stream)', () async {
      for (int i = 1; i < 10; ++i) {
        var key = randomNumbers(32);
        var nonce = randomBytes(12);
        for (int j = 0; j < 100; ++j) {
          var text = randomNumbers(j);
          var bytes = Uint8List.fromList(text);
          var stream = Stream.fromIterable(text);
          var cipherStream = chacha20Pipe(stream, key, nonce);
          var plainStream = chacha20Pipe(cipherStream, key, nonce);
          var plain = await plainStream.toList();
          expect(bytes, equals(plain), reason: '[key: $i, text: $j]');
        }
      }
    });
  });
}
