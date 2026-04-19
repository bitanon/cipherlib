// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/random.dart';
import 'package:cipherlib/codecs.dart';
import 'package:test/test.dart';

void main() {
  group('validation', () {
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
      expect(() => AESInPCBCMode(key).encrypt(input), returnsNormally);
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
