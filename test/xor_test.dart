// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/codecs.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  test('empty key with empty message', () {
    expect(() => xor([], []), throwsArgumentError);
  });
  test('empty key with some message', () {
    expect(() => xor([1], []), throwsArgumentError);
  });
  test('empty message', () {
    expect(xor([], [1]), equals([]));
  });
  test('known message', () {
    var key = 'key'.codeUnits;
    var plain = 'plaintext'.codeUnits;
    var cipher = fromHex('1b0918020b0d0e1d0d');
    var out = xor(plain, key);
    expect(toHex(out), equals(toHex(cipher)));
    var rev = xor(cipher, key);
    expect(toHex(rev), equals(toHex(plain)));
  });
  test('encryption <-> decryption (convert)', () {
    for (int i = 1; i < 100; i += 10) {
      var key = randomNumbers(i);
      for (int j = 0; j < 100; j += 5) {
        var text = randomNumbers(j);
        var bytes = Uint8List.fromList(text);
        var cipher = xor(text, key);
        var plain = xor(cipher, key);
        expect(bytes, equals(plain), reason: '[key: $i, text: $j]');
      }
    }
  });
  test('encryption <-> decryption (stream)', () async {
    for (int i = 1; i < 10; ++i) {
      var key = randomNumbers(i);
      for (int j = 0; j < 100; j += 8) {
        var text = randomNumbers(j);
        var bytes = Uint8List.fromList(text);
        var stream = Stream.fromIterable(text);
        var cipherStream = xorStream(stream, key);
        var plainStream = xorStream(cipherStream, key);
        var plain = await plainStream.toList();
        expect(bytes, equals(plain), reason: '[key: $i, text: $j]');
      }
    }
  });
  test('single instance', () {
    for (int i = 1; i < 20; ++i) {
      var key = randomNumbers(i);
      var instance = XOR.fromList(key);
      for (int j = 0; j < 100; j += 12) {
        var text = randomNumbers(j);
        var bytes = Uint8List.fromList(text);
        var cipher = instance.convert(bytes);
        var plain = instance.convert(cipher);
        expect(bytes, equals(plain), reason: '[key: $i, text: $j]');
      }
    }
  });

  test('sink test (no add after close)', () {
    var key = Uint8List.fromList(
      List.generate(16, (i) => i),
    );
    var sample = Uint8List(64);
    var output = List.generate(64, (i) => i % 16);
    var sink = XOR(key).createSink();
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
