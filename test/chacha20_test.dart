// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/codecs.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  group('Functionality test', () {
    test('name', () {
      expect(ChaCha20(Uint8List(32)).name, "ChaCha20");
    });
    test('accepts empty message', () {
      var key = randomNumbers(32);
      var nonce = randomBytes(12);
      expect(chacha20([], key, nonce: nonce), equals([]));
    });
    test('The key should be either 16 or 32 bytes', () {
      for (int i = 0; i < 100; ++i) {
        void cb() => chacha20([1], Uint8List(i));
        if (i == 16 || i == 32) {
          cb();
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('The nonce should be either 8, 12 or 16 bytes', () {
      var key = Uint8List(32);
      for (int i = 0; i < 100; ++i) {
        void cb() => chacha20([1], key, nonce: Uint8List(i));
        if (i == 8 || i == 12 || i == 16) {
          cb();
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('Counter is not expected with 16-byte nonce', () {
      final key = Uint8List(32);
      final c = Nonce64.zero();
      expect(() => ChaCha20(key, Uint8List(16), c), throwsArgumentError);
    });
    test('Default counter is used when not provided with 12-byte nonce', () {
      final key = Uint8List(32);
      final nonce = List.filled(12, 1);
      final algo = ChaCha20(key, nonce);
      expect(algo.iv, equals([1, 0, 0, 0, ...nonce]));
    });
    test('Counter is set correctly when provided with 12-byte nonce', () {
      final key = Uint8List(32);
      final nonce = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
      final counter = Nonce64.bytes([2, 2, 2, 2]);
      final algo = ChaCha20(key, nonce, counter);
      expect(algo.iv, equals([2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]));
    });
    test('Default counter is used when not provided with 8-byte nonce', () {
      final key = Uint8List(32);
      final nonce = [1, 1, 1, 1, 1, 1, 1, 1];
      final algo = ChaCha20(key, nonce);
      expect(algo.iv, equals([1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]));
    });
    test('Counter is set correctly when provided with 8-byte nonce', () {
      final key = Uint8List(32);
      final nonce = [1, 1, 1, 1, 1, 1, 1, 1];
      final counter = Nonce64.bytes([2, 2, 2, 2, 2, 2, 2, 2]);
      final algo = ChaCha20(key, nonce, counter);
      expect(algo.iv, equals([2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1]));
    });
    test('random nonce is used if nonce is null, ', () {
      var key = randomNumbers(32);
      var text = randomBytes(100);
      chacha20(text, key);
    });
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

  group('correctness', () {
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
  });

  group('counter increment', () {
    test('at 32-bit with 8-byte nonce', () {
      var key = randomBytes(32);
      var iv = fromHex('3122331221327845');
      var counter1 = Nonce64.int32(0xFFFFFFFF, 0x0F0F0FFF);
      var counter2 = Nonce64.int32(1, 0x0F0F1000);
      var message = Uint8List(256);
      var out1 = chacha20(message, key, nonce: iv, counter: counter1);
      var out2 = chacha20(message, key, nonce: iv, counter: counter2);
      expect(out1.skip(128), equals(out2.take(128)));
    });

    test('at 64-bit with 8-byte nonce', () {
      var key = randomBytes(32);
      var iv = fromHex('3122331221327845');
      var counter1 = Nonce64.int32(0xFFFFFFFF, 0xFFFFFFFF);
      var counter2 = Nonce64.int32(1);
      var message = Uint8List(256);
      var out1 = chacha20(message, key, nonce: iv, counter: counter1);
      var out2 = chacha20(message, key, nonce: iv, counter: counter2);
      expect(out1.skip(128), equals(out2.take(128)));
    });

    test('at 32-bit with 12-byte nonce', () {
      var key = randomBytes(32);
      var iv = fromHex('FF0F0F0F3122331221327845');
      var counter1 = Nonce64.int32(0xFFFFFFFF, 0xFFFFFFFF);
      var counter2 = Nonce64.int32(1, 0xFFFFFFFF);
      var message = Uint8List(256);
      var out1 = chacha20(message, key, nonce: iv, counter: counter1);
      var out2 = chacha20(message, key, nonce: iv, counter: counter2);
      expect(out1.skip(128), equals(out2.take(128)));
    });

    test('at 32-bit with 16-byte nonce', () {
      var key = randomBytes(32);
      var nonce1 = fromHex('FFFFFFFFFF0F0F0F3122331221327845');
      var nonce2 = fromHex('0100000000100F0F3122331221327845');
      var message = Uint8List(256);
      var out1 = chacha20(message, key, nonce: nonce1);
      var out2 = chacha20(message, key, nonce: nonce2);
      expect(out1.skip(128), equals(out2.take(128)));
    });

    test('at 64-bit with 16-byte nonce', () {
      var key = randomBytes(32);
      var nonce1 = fromHex('FFFFFFFFFFFFFFFF3122331221327845');
      var nonce2 = fromHex('01000000000000003122331221327845');
      var message = Uint8List(256);
      var out1 = chacha20(message, key, nonce: nonce1);
      var out2 = chacha20(message, key, nonce: nonce2);
      expect(out1.skip(128), equals(out2.take(128)));
    });
  });

  test('Sink operations', () {
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
    var sink = ChaCha20(key, nonce).createSink();
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
