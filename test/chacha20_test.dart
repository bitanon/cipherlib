// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  test('empty message', () {
    var key = randomNumbers(32);
    var nonce = randomBytes(12);
    expect(chacha20([], key, nonce: nonce), equals([]));
  });
  test('key length is not 32 bytes', () {
    var text = randomNumbers(32);
    expect(() => chacha20(text, []), throwsArgumentError);
    expect(() => chacha20(text, Uint8List(33)), throwsArgumentError);
    expect(() => chacha20(text, Uint8List(31)), throwsArgumentError);
  });
  test('nonce is null', () {
    var key = randomNumbers(32);
    var text = randomBytes(100);
    chacha20(text, key);
  });
  test('nonce length is not 12 bytes', () {
    var key = Uint8List(32);
    var text = Uint8List(100);
    expect(() => chacha20(text, key, nonce: [1]), throwsArgumentError);
  });
  test('counter length is not 8 or 4 bytes', () {
    var key = Uint8List(32);
    var iv8 = Uint8List(8);
    var iv12 = Uint8List(12);
    for (int i = 0; i < 4; ++i) {
      expect(() => ChaCha20Sink(key, iv8, Uint8List(i)), throwsArgumentError);
      expect(() => ChaCha20Sink(key, iv12, Uint8List(i)), throwsArgumentError);
    }
    for (int i = 4; i < 8; ++i) {
      ChaCha20Sink(key, iv12, Uint8List(i));
      expect(() => ChaCha20Sink(key, iv8, Uint8List(i)), throwsArgumentError);
    }
    for (int i = 8; i < 16; ++i) {
      ChaCha20Sink(key, iv8, Uint8List(i));
      ChaCha20Sink(key, iv12, Uint8List(i));
    }
  });
  test('RFC 8439 example-1', () {
    var key = fromHex(
      "000102030405060708090a0b0c0d0e0f"
      "101112131415161718191a1b1c1d1e1f",
    );
    var nonce = fromHex(
      "000000000000004a00000000",
    );
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
    var cipher = chacha20(sample.codeUnits, key, nonce: nonce);
    expect(output, equals(cipher));
  });
  test('RFC 8439 example-2', () {
    var key = fromHex(
      "808182838485868788898a8b8c8d8e8f"
      "909192939495969798999a9b9c9d9e9f",
    );
    var nonce = fromHex(
      "070000004041424344454647",
    );
    var sample = "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    var output = fromHex(
      "d31a8d34648e60db7b86afbc53ef7ec2"
      "a4aded51296e08fea9e2b5a736ee62d6"
      "3dbea45e8ca9671282fafb69da92728b"
      "1a71de0a9e060b2905d6a5b67ecd3b36"
      "92ddbd7f2d778b8c9803aee328091b58"
      "fab324e4fad675945585808b4831d7bc"
      "3ff4def08e4b7a9de576d26586cec64b"
      "6116",
    );
    var cipher = chacha20(sample.codeUnits, key, nonce: nonce);
    expect(output, equals(cipher));
  });
  test('encryption <-> decryption (convert)', () {
    var key = randomNumbers(32);
    var nonce = randomBytes(12);
    for (int j = 0; j < 100; ++j) {
      var text = randomNumbers(j);
      var bytes = Uint8List.fromList(text);
      var cipher = chacha20(text, key, nonce: nonce);
      var plain = chacha20(cipher, key, nonce: nonce);
      expect(bytes, equals(plain), reason: '[text: $j]');
    }
  });
  test('encryption <-> decryption (stream)', () async {
    var key = randomNumbers(16);
    var nonce = randomBytes(12);
    for (int j = 0; j < 100; ++j) {
      var text = randomNumbers(j);
      var bytes = Uint8List.fromList(text);
      var stream = Stream.fromIterable(text);
      var cipherStream = chacha20Stream(stream, key, nonce: nonce);
      var plainStream = chacha20Stream(cipherStream, key, nonce: nonce);
      var plain = await plainStream.toList();
      expect(bytes, equals(plain), reason: '[text: $j]');
    }
  });
  test('8-byte nonce: encryption <-> decryption (convert)', () {
    var key = randomNumbers(32);
    var nonce = randomBytes(8);
    for (int j = 0; j < 100; ++j) {
      var text = randomNumbers(j);
      var bytes = Uint8List.fromList(text);
      var cipher = chacha20(text, key, nonce: nonce);
      var plain = chacha20(cipher, key, nonce: nonce);
      expect(bytes, equals(plain), reason: '[text: $j]');
    }
  });

  test('sink test (no add after close)', () {
    var key = fromHex(
      "000102030405060708090a0b0c0d0e0f"
      "101112131415161718191a1b1c1d1e1f",
    );
    var nonce = fromHex(
      "000000000000004a00000000",
    );
    var sample = ("Ladies and Gentlemen of the class of '99: "
            "If I could offer you only one tip for the future, "
            "sunscreen would be it.")
        .codeUnits;
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
    var counter = Nonce64.int32(1).bytes;
    var sink = ChaCha20Sink(key, nonce, counter);
    int step = 19;
    for (int i = 0; i < sample.length; i += step) {
      var inp = sample.skip(i).take(step).toList();
      var out = output.skip(i).take(step).toList();
      expect(sink.add(inp), equals(out));
    }
    expect(sink.close(), equals([]));
    expect(sink.closed, true);
    expect(() => sink.add([1]), throwsStateError);
    sink.reset();
    expect(sink.add(sample), equals(output));
  });
}
