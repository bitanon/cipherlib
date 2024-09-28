// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/random.dart';
import 'package:hashlib/codecs.dart';
import 'package:test/test.dart';

void main() {
  group("functionality tests", () {
    final key = Uint8List(32);
    final iv = Uint8List(16);
    final input = Uint8List(64);
    test("name is correct", () {
      expect(AES.noPadding(key).pcbc(iv).name, "AES/PCBC/NoPadding");
      expect(AES.ansi(key).pcbc(iv).name, "AES/PCBC/ANSI");
      expect(AES.byte(key).pcbc(iv).name, "AES/PCBC/Byte");
      expect(AES.pkcs7(key).pcbc(iv).name, "AES/PCBC/PKCS7");
    });
    test("padding is correct", () {
      expect(AES.noPadding(key).pcbc(iv).padding, Padding.none);
      expect(AES.ansi(key).pcbc(iv).padding, Padding.ansi);
      expect(AES.byte(key).pcbc(iv).padding, Padding.byte);
      expect(AES.pkcs7(key).pcbc(iv).padding, Padding.pkcs7);
    });
    test("accepts null IV", () {
      AESInPCBCMode(key).encrypt(input);
    });
    test("encryptor name is correct", () {
      expect(AES.noPadding(key).pcbc(iv).encryptor.name,
          "AES#encrypt/PCBC/NoPadding");
      expect(AES.ansi(key).pcbc(iv).encryptor.name, "AES#encrypt/PCBC/ANSI");
      expect(AES.byte(key).pcbc(iv).encryptor.name, "AES#encrypt/PCBC/Byte");
      expect(AES.pkcs7(key).pcbc(iv).encryptor.name, "AES#encrypt/PCBC/PKCS7");
    });
    test("decryptor name is correct", () {
      expect(AES.noPadding(key).pcbc(iv).decryptor.name,
          "AES#decrypt/PCBC/NoPadding");
      expect(AES.ansi(key).pcbc(iv).decryptor.name, "AES#decrypt/PCBC/ANSI");
      expect(AES.byte(key).pcbc(iv).decryptor.name, "AES#decrypt/PCBC/Byte");
      expect(AES.pkcs7(key).pcbc(iv).decryptor.name, "AES#decrypt/PCBC/PKCS7");
    });
    test('encryptor sink test (no add after close)', () {
      final aes = AES.noPadding(key).pcbc(iv);
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
      final aes = AES.noPadding(key).pcbc(iv);
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
      var aes = AES.noPadding(Uint8List(16)).pcbc(Uint8List(16));
      expect(() => aes.encrypt(Uint8List(10)), throwsStateError);
      expect(() => aes.decrypt(Uint8List(10)), throwsStateError);
      expect(() => aes.encrypt(Uint8List(17)), throwsStateError);
      expect(() => aes.decrypt(Uint8List(17)), throwsStateError);
    });
    test('throws error on invalid salt size', () {
      var aes = AES(Uint8List(16));
      expect(() => aes.pcbc(Uint8List(15)).encrypt([0]), throwsStateError);
      expect(() => aes.pcbc(Uint8List(8)).decrypt([0]), throwsStateError);
      expect(aes.pcbc(Uint8List(16)).encrypt([]).length, 16);
    });
  });

  group('encryption <-> decryption', () {
    test("128-bit", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).pcbc(iv).encrypt(inp);
        var plain = AES(key).pcbc(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("192-bit", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).pcbc(iv).encrypt(inp);
        var plain = AES(key).pcbc(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("256-bit", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).pcbc(iv).encrypt(inp);
        var plain = AES(key).pcbc(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
  });

  group('sink test', () {
    test('encryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = randomBytes(16);
        final aes = AES(key).pcbc(iv);

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
        var iv = randomBytes(16);
        final aes = AES(key).pcbc(iv);

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
        var iv = randomBytes(16);
        var input = randomBytes(j);

        final aes = AES(key).pcbc(iv);
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
    var iv = randomBytes(16);
    var key = randomBytes(24);
    var aes = AES(key).pcbc(iv);
    for (int j = 0; j < 100; j++) {
      aes.resetIV();
      var inp = randomBytes(j);
      var cipher = aes.encrypt(inp);
      var plain = aes.decrypt(cipher);
      expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
    }
  });
}
