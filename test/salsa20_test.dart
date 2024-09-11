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
      expect(Salsa20(Uint8List(32)).name, "Salsa20");
    });
    test('accepts empty message', () {
      var key = randomNumbers(32);
      var nonce = randomBytes(16);
      expect(salsa20([], key, nonce: nonce), equals([]));
    });
    test('The key should be either 16 or 32 bytes', () {
      for (int i = 0; i < 100; ++i) {
        void cb() => Salsa20(Uint8List(i));
        if (i == 16 || i == 32) {
          cb();
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('The nonce should be either 8, or 16 bytes', () {
      var key = Uint8List(32);
      for (int i = 0; i < 100; ++i) {
        void cb() => Salsa20(key, Uint8List(i));
        if (i == 8 || i == 16) {
          cb();
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('Counter is not expected with 16-byte nonce', () {
      final key = Uint8List(32);
      final c = Nonce64.zero();
      expect(() => Salsa20(key, Uint8List(16), c), throwsArgumentError);
    });
    test('If counter is not provided, default counter is used', () {
      final key = Uint8List(32);
      final nonce = [1, 1, 1, 1, 1, 1, 1, 1];
      final algo = Salsa20(key, nonce);
      expect(algo.iv, equals([1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]));
    });
    test('Counter is set correctly when provided with 8-byte nonce', () {
      final key = Uint8List(32);
      final nonce = [1, 1, 1, 1, 1, 1, 1, 1];
      final counter = Nonce64.bytes([2, 2, 2, 2, 2, 2, 2, 2]);
      final algo = Salsa20(key, nonce, counter);
      expect(algo.iv, equals([1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2]));
    });
    test('random nonce is used if nonce is null, ', () {
      var key = randomNumbers(32);
      var text = randomBytes(100);
      chacha20(text, key);
    });
  });

  test('Specification example (32-bytes key)', () {
    var key = [
      ...List.generate(16, (i) => i + 1),
      ...List.generate(16, (i) => i + 201),
    ];
    var nonce = List.generate(16, (i) => i + 101);
    var sample = Uint8List(64);
    var output = [
      69, 37, 68, 39, 41, 15, 107, 193, 255, 139, 122, 6, 170, 233, 217, //
      98, 89, 144, 182, 106, 21, 51, 200, 65, 239, 49, 222, 34, 215, 114, 40,
      126, 104, 197, 7, 225, 197, 153, 31, 2, 102, 78, 76, 176, 84, 245, 246,
      184, 177, 160, 133, 130, 6, 72, 149, 119, 192, 195, 132, 236, 234, 103,
      246, 74
    ];
    var cipher = salsa20(sample, key, nonce: nonce);
    expect(output, equals(cipher));
  });
  test('Specification example (16-bytes key)', () {
    var key = List.generate(16, (i) => i + 1);
    var nonce = List.generate(16, (i) => i + 101);
    var sample = Uint8List(64);
    var output = [
      39, 173, 46, 248, 30, 200, 82, 17, 48, 67, 254, 239, 37, 18, 13, //
      247, 241, 200, 61, 144, 10, 55, 50, 185, 6, 47, 246, 253, 143, 86, 187,
      225, 134, 85, 110, 246, 161, 163, 43, 235, 231, 94, 171, 51, 145, 214,
      112, 29, 14, 232, 5, 16, 151, 140, 183, 141, 171, 9, 122, 181, 104, 182,
      177, 193
    ];
    var cipher = salsa20(sample, key, nonce: nonce);
    expect(output, equals(cipher));
  });

  group('correctness', () {
    test('encryption <-> decryption (convert)', () {
      var key = randomNumbers(32);
      var nonce = randomBytes(16);
      for (int j = 0; j < 100; ++j) {
        var text = randomNumbers(j);
        var bytes = Uint8List.fromList(text);
        var cipher = salsa20(text, key, nonce: nonce);
        var plain = salsa20(cipher, key, nonce: nonce);
        expect(bytes, equals(plain), reason: '[text: $j]');
      }
    });
    test('encryption <-> decryption (stream)', () async {
      var key = randomNumbers(32);
      var nonce = randomBytes(16);
      for (int j = 0; j < 100; ++j) {
        var text = randomNumbers(j);
        var bytes = Uint8List.fromList(text);
        var stream = Stream.fromIterable(text);
        var cipherStream = salsa20Stream(stream, key, nonce: nonce);
        var plainStream = salsa20Stream(cipherStream, key, nonce: nonce);
        var plain = await plainStream.toList();
        expect(plain, equals(bytes), reason: '[text: $j]');
      }
    });
    test('8-byte nonce: encryption <-> decryption (convert)', () {
      var key = randomNumbers(32);
      var nonce = randomBytes(8);
      for (int j = 0; j < 100; ++j) {
        var text = randomNumbers(j);
        var plain = Uint8List.fromList(text);
        var cipher = salsa20(text, key, nonce: nonce);
        var backwards = salsa20(cipher, key, nonce: nonce);
        expect(plain, equals(backwards), reason: '[text: $j]');
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
      var out1 = salsa20(message, key, nonce: iv, counter: counter1);
      var out2 = salsa20(message, key, nonce: iv, counter: counter2);
      expect(out1.skip(128), equals(out2.take(128)));
    });

    test('at 64-bit with 8-byte nonce', () {
      var key = randomBytes(32);
      var iv = fromHex('3122331221327845');
      var counter1 = Nonce64.int32(0xFFFFFFFF, 0xFFFFFFFF);
      var counter2 = Nonce64.int32(1);
      var message = Uint8List(256);
      var out1 = salsa20(message, key, nonce: iv, counter: counter1);
      var out2 = salsa20(message, key, nonce: iv, counter: counter2);
      expect(out1.skip(128), equals(out2.take(128)));
    });

    test('at 32-bit with 16-byte nonce', () {
      var key = randomBytes(32);
      var nonce1 = fromHex('3122331221327845FFFFFFFFFF0F0F0F');
      var nonce2 = fromHex('31223312213278450100000000100F0F');
      var message = Uint8List(256);
      var out1 = salsa20(message, key, nonce: nonce1);
      var out2 = salsa20(message, key, nonce: nonce2);
      expect(out1.skip(128), equals(out2.take(128)));
    });

    test('at 64-bit with 16-byte nonce', () {
      var key = randomBytes(32);
      var nonce1 = fromHex('3122331221327845FFFFFFFFFFFFFFFF');
      var nonce2 = fromHex('31223312213278450100000000000000');
      var message = Uint8List(256);
      var out1 = salsa20(message, key, nonce: nonce1);
      var out2 = salsa20(message, key, nonce: nonce2);
      expect(out1.skip(128), equals(out2.take(128)));
    });
  });

  test('Sink operations', () {
    var key = Uint8List.fromList(
      List.generate(16, (i) => i + 1),
    );
    var nonce = Uint8List.fromList(
      List.generate(16, (i) => i + 101),
    );
    var sample = Uint8List(64);
    var output = [
      39, 173, 46, 248, 30, 200, 82, 17, 48, 67, 254, 239, 37, 18, 13, //
      247, 241, 200, 61, 144, 10, 55, 50, 185, 6, 47, 246, 253, 143, 86, 187,
      225, 134, 85, 110, 246, 161, 163, 43, 235, 231, 94, 171, 51, 145, 214,
      112, 29, 14, 232, 5, 16, 151, 140, 183, 141, 171, 9, 122, 181, 104, 182,
      177, 193
    ];
    var sink = Salsa20(key, nonce).createSink();
    int step = 8;
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
