// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  test('empty message', () {
    var key = randomNumbers(32);
    var nonce = randomBytes(16);
    expect(salsa20([], key, nonce: nonce), equals([]));
  });
  test('key length is not 32 bytes', () {
    var text = randomNumbers(32);
    expect(() => salsa20(text, []), throwsArgumentError);
    expect(() => salsa20(text, Uint8List(33)), throwsArgumentError);
    expect(() => salsa20(text, Uint8List(31)), throwsArgumentError);
  });
  test('nonce is null', () {
    var key = randomNumbers(32);
    var text = randomBytes(100);
    salsa20(text, key);
  });
  test('nonce length is not 12 bytes', () {
    var key = Uint8List(32);
    var text = Uint8List(100);
    expect(() => salsa20(text, key, nonce: [1]), throwsArgumentError);
  });
  test('counter length is not 8 bytes when nonce is 8 bytes', () {
    var key = Uint8List(32);
    var iv8 = Uint8List(8);
    var iv16 = Uint8List(16);
    for (int i = 0; i < 8; ++i) {
      Salsa20Sink(key, iv16, Uint8List(i));
      expect(() => Salsa20Sink(key, iv8, Uint8List(i)), throwsArgumentError);
    }
    for (int i = 8; i < 16; ++i) {
      Salsa20Sink(key, iv8, Uint8List(i));
      Salsa20Sink(key, iv16, Uint8List(i));
    }
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

  test('sink test (no add after close)', () {
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
    var counter = Nonce64.zero().bytes;
    var sink = Salsa20Sink(key, nonce, counter);
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
