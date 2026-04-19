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
      expect(() => AESInIGEMode(key).encrypt(input), returnsNormally);
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
