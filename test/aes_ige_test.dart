// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/hashlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

void main() {
  group("functionality tests", () {
    final key = Uint8List(32);
    final iv = Uint8List(16);
    final input = Uint8List(64);
    test("name is correct", () {
      expect(AES.noPadding(key).ige(iv).name, "AES/IGE/NoPadding");
      expect(AES.ansi(key).ige(iv).name, "AES/IGE/ANSI");
      expect(AES.byte(key).ige(iv).name, "AES/IGE/Byte");
      expect(AES.pkcs7(key).ige(iv).name, "AES/IGE/PKCS7");
    });
    test("padding is correct", () {
      expect(AES.noPadding(key).ige(iv).padding, Padding.none);
      expect(AES.ansi(key).ige(iv).padding, Padding.ansi);
      expect(AES.byte(key).ige(iv).padding, Padding.byte);
      expect(AES.pkcs7(key).ige(iv).padding, Padding.pkcs7);
    });
    test("accepts null IV", () {
      AESInIGEMode(key).encrypt(input);
    });
    test("encryptor name is correct", () {
      expect(AES.noPadding(key).ige(iv).encryptor.name,
          "AES#encrypt/IGE/NoPadding");
      expect(AES.ansi(key).ige(iv).encryptor.name, "AES#encrypt/IGE/ANSI");
      expect(AES.byte(key).ige(iv).encryptor.name, "AES#encrypt/IGE/Byte");
      expect(AES.pkcs7(key).ige(iv).encryptor.name, "AES#encrypt/IGE/PKCS7");
    });
    test("decryptor name is correct", () {
      expect(AES.noPadding(key).ige(iv).decryptor.name,
          "AES#decrypt/IGE/NoPadding");
      expect(AES.ansi(key).ige(iv).decryptor.name, "AES#decrypt/IGE/ANSI");
      expect(AES.byte(key).ige(iv).decryptor.name, "AES#decrypt/IGE/Byte");
      expect(AES.pkcs7(key).ige(iv).decryptor.name, "AES#decrypt/IGE/PKCS7");
    });
    test('encryptor sink test (no add after close)', () {
      final aes = AES.noPadding(key).ige(iv);
      var sink = aes.encryptor.createSink();
      int step = 8;
      var output = [];
      for (int i = 0; i < input.length; i += step) {
        output.addAll(sink.add(input.skip(i).take(step).toList()));
      }
      output.addAll(sink.close());
      expect(sink.closed, true);
      expect(output, equals(aes.encrypt(input)));
      expect(() => sink.add(Uint8List(16)), throwsStateError);
      sink.reset();
      expect([...sink.add(input), ...sink.close()], equals(output));
    });
    test('decryptor sink test (no add after close)', () {
      final aes = AES.noPadding(key).ige(iv);
      var ciphertext = aes.encrypt(input);
      var sink = aes.decryptor.createSink();
      int step = 8;
      var output = [];
      for (int i = 0; i < ciphertext.length; i += step) {
        output.addAll(sink.add(ciphertext.skip(i).take(step).toList()));
      }
      output.addAll(sink.close());
      expect(sink.closed, true);
      expect(output, equals(input));
      expect(() => sink.add(Uint8List(16)), throwsStateError);
      sink.reset();
      expect([...sink.add(ciphertext), ...sink.close()], equals(output));
    });
    test('throws error on invalid input size', () {
      var aes = AES.noPadding(Uint8List(16)).ige(Uint8List(32));
      expect(() => aes.encrypt(Uint8List(10)), throwsStateError);
      expect(() => aes.decrypt(Uint8List(10)), throwsStateError);
      expect(() => aes.encrypt(Uint8List(17)), throwsStateError);
      expect(() => aes.decrypt(Uint8List(17)), throwsStateError);
    });
    test('throws error on invalid salt size', () {
      var aes = AES(Uint8List(16));
      expect(() => aes.ige(Uint8List(0)).decrypt([0]), throwsStateError);
      expect(() => aes.ige(Uint8List(15)).encrypt([0]), throwsStateError);
      expect(aes.ige(Uint8List(16)).encrypt([]).length, 16);
    });
  });

  group('empty message', () {
    var aes = AES.noPadding(Uint8List(32)).ige(Uint8List(32));
    test('encrypt', () {
      var actual = aes.encrypt([]);
      expect(toHex(actual), equals(toHex([])));
    });
    test('decrypt', () {
      var reverse = aes.decrypt([]);
      expect(toHex(reverse), equals(toHex([])));
    });
  });

  group('encryption <-> decryption', () {
    test("128-bit", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(32);
        var cipher = AES(key).ige(iv).encrypt(inp);
        var plain = AES(key).ige(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("192-bit", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(32);
        var cipher = AES(key).ige(iv).encrypt(inp);
        var plain = AES(key).ige(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("256-bit", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(32);
        var cipher = AES(key).ige(iv).encrypt(inp);
        var plain = AES(key).ige(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
  });

  group('sink test', () {
    test('encryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = randomBytes(32);
        final aes = AES(key).ige(iv);

        var input = randomBytes(j);
        var cipher = aes.encrypt(input);

        var enc = aes.encryptor.createSink();
        var output = <int>[];
        for (int i = 0; i < input.length; i += 13) {
          output.addAll(enc.add(input.skip(i).take(13).toList()));
        }
        output.addAll(enc.close());
        expect(toHex(output), equals(toHex(cipher)), reason: '[size: $j]');

        var plain = aes.decrypt(output);
        expect(toHex(plain), equals(toHex(input)), reason: '[size: $j]');
      }
    });
    test('decryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = randomBytes(32);
        final aes = AES(key).ige(iv);

        var input = randomBytes(j);
        var cipher = aes.encrypt(input);

        var dec = aes.decryptor.createSink();
        var output = <int>[];
        for (int i = 0; i < cipher.length; i += 23) {
          output.addAll(dec.add(cipher.skip(i).take(23).toList()));
        }
        output.addAll(dec.close());
        expect(toHex(output), equals(toHex(input)), reason: '[size: $j]');
      }
    });
    test('encryption + decryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = randomBytes(32);
        var input = randomBytes(j);

        final aes = AES(key).ige(iv);
        var enc = aes.encryptor.createSink();
        var dec = aes.decryptor.createSink();

        var output = <int>[];
        for (int i = 0; i < input.length; i += 23) {
          var part = input.skip(i).take(23).toList();
          output.addAll(dec.add(enc.add(part)));
        }
        output.addAll(dec.add(enc.close()));
        output.addAll(dec.close());
        expect(toHex(output), equals(toHex(input)), reason: '[size: $j]');
      }
    });
  });

  test('reset iv', () {
    var iv = randomBytes(32);
    var key = randomBytes(24);
    var aes = AES(key).ige(iv);
    for (int j = 0; j < 100; j++) {
      aes.resetIV();
      var inp = randomBytes(j);
      var cipher = aes.encrypt(inp);
      var plain = aes.decrypt(cipher);
      expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
    }
  });
}
