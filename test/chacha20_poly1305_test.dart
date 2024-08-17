// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

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
      var tag = fromHex('1ae10b594f09e26a7e902ecbd0600691');
      var res = chacha20poly1305(
        sample.codeUnits,
        key,
        nonce: nonce,
        aad: aad,
      );
      expect(res.tag.bytes, equals(tag));
      expect(res.verify(tag), true);
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
        res.data,
        key,
        mac: res.tag.bytes,
        nonce: nonce,
        aad: aad,
      );
      expect(verified.data, equals(sample.codeUnits));
    });
    test('decrypt with invalid mac', () {
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
        throwsA((e) => e is AssertionError),
      );
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

  group('functionality tests', () {
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
    var algo = ChaCha20Poly1305(
      key: key,
      aad: aad,
      nonce: nonce,
    );

    test('defines name correctly', () {
      expect(algo.name, "ChaCha20/Poly1305");
    });
    test('accepts integer stream', () async {
      var stream = Stream.fromIterable(sample);
      var output = await algo.stream(stream).toList();
      expect(output, equals(cipher));
    });
    test('accepts large integer stream', () async {
      var input = List.generate(1200, (index) => index);
      var stream = Stream.fromIterable(input);
      var output = await algo.stream(stream).toList();
      var expected = algo.convert(input).data;
      expect(output, equals(expected));
    });
    test('accepts integer stream with onDigest callback', () async {
      final done = Completer();
      var stream = Stream.fromIterable(sample);
      var outputStream = algo.stream(stream, (tag) {
        expect(tag.hex(), equals('1ae10b594f09e26a7e902ecbd0600691'));
        done.complete();
      });
      var output = await outputStream.toList();
      expect(output, equals(cipher));
      await done.future;
    });
    test('binds stream', () async {
      var grouped = [
        "Ladies and Gentlemen of the class of '99: ".codeUnits,
        "If I could offer you only one tip for the future, ".codeUnits,
        "sunscreen would be it.".codeUnits,
      ];
      var stream = Stream.fromIterable(grouped);
      var output = [];
      await for (var out in algo.bind(stream)) {
        output.addAll(out);
      }
      expect(output, equals(cipher));
    });
    test('binds large stream', () async {
      var input = List.generate(1200, (index) => index);
      var stream = Stream.fromIterable([input]);
      var output = [];
      await for (var out in algo.bind(stream)) {
        output.addAll(out);
      }
      var expected = algo.convert(input).data;
      expect(output, equals(expected));
    });
    test('binds stream with onDigest call', () async {
      final done = Completer();
      var grouped = [
        "Ladies and Gentlemen of the class of '99: ".codeUnits,
        "If I could offer you only one tip for the future, ".codeUnits,
        "sunscreen would be it.".codeUnits,
      ];
      var stream = Stream.fromIterable(grouped);
      var outputStream = algo.bind(stream, (tag) {
        expect(tag.hex(), equals('1ae10b594f09e26a7e902ecbd0600691'));
        done.complete();
      });
      var output = [];
      await for (var out in outputStream) {
        output.addAll(out);
      }
      expect(output, equals(cipher));
      await done.future;
    });
    test('sink test (no call after close)', () {
      var sink = algo.createSink();
      expect(sink.hashLength, 16);
      expect(sink.derivedKeyLength, 16);

      int step = 19;
      for (int i = 0; i < sample.length; i += step) {
        var inp = sample.skip(i).take(step).toList();
        var out = cipher.skip(i).take(step).toList();
        expect(sink.add(inp), equals(out));
      }
      expect(sink.close(), equals([]));
      expect(sink.closed, true);
      expect(sink.digest().hex(), '1ae10b594f09e26a7e902ecbd0600691');

      expect(() => sink.add([1]), throwsStateError);

      sink.reset(true);
      expect(sink.add(sample), equals(cipher));
      expect(sink.digest().hex(), '67a0fa25b34192a2844b8bbde2e76c92');
    });
  });
}
