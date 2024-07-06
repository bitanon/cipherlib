// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/hashlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

void main() {
  group("encryption", () {
    test('throws error on invalid input size', () {
      var key = Uint32List(16);
      var inp = Uint32List(10);
      var iv = randomBytes(16);
      expect(() => AES.noPadding(key).cbc(iv).encrypt(inp), throwsStateError);
    });
    test('128-bit with PKCS#7 padding', () {
      var inp = 'A not very secret message'.codeUnits;
      var key = 'abcdefghijklmnop'.codeUnits;
      var salt = 'lka9JLKasljkdPsd'.codeUnits;
      var expected =
          '07FD872F06478F991FFFCA2C649F4D5C1C7F769E4001541ACCF97639B9C8D750';
      var actual = AES(key).cbc(salt).encrypt(inp);
      expect(toHex(actual, upper: true), equals(expected));
    });
    test('192-bit with PKCS#7 padding', () {
      var inp = 'A not very secret message'.codeUnits;
      var key = 'abcdefghijklmnopqrstuvwx'.codeUnits;
      var salt = 'lka9JLKasljkdPsd'.codeUnits;
      var expected =
          '1FAF5E6B855A8F48A38BA6F0C68260EF22CA50E3E00D9F567149F7D66E8981E5';
      var actual = AES(key).cbc(salt).encrypt(inp);
      expect(toHex(actual, upper: true), equals(expected));
    });
    test('256-bit with PKCS#7 padding', () {
      var inp = 'A not very secret message'.codeUnits;
      var key = 'abcdefghijklmnopqrstuvwxyz012345'.codeUnits;
      var salt = 'lka9JLKasljkdPsd'.codeUnits;
      var expected =
          '55D9375493876E2DE608BFFDE6AFF486A4FF0671B84BB39A0A62D8312D5B631A';
      var actual = AES(key).cbc(salt).encrypt(inp);
      expect(toHex(actual, upper: true), equals(expected));
    });
  });

  group("decryption", () {
    test('throws error on invalid input size', () {
      var key = Uint32List(16);
      var inp = Uint32List(10);
      var iv = randomBytes(16);
      expect(() => AES.noPadding(key).cbc(iv).decrypt(inp), throwsStateError);
    });
    test('128-bit with PKCS#7 padding', () {
      var inp = fromHex(
          '07FD872F06478F991FFFCA2C649F4D5C1C7F769E4001541ACCF97639B9C8D750');
      var key = 'abcdefghijklmnop'.codeUnits;
      var salt = 'lka9JLKasljkdPsd'.codeUnits;
      var expected = 'A not very secret message';
      var actual = AES(key).cbc(salt).decrypt(inp);
      expect(String.fromCharCodes(actual), equals(expected));
    });
    test('192-bit with PKCS#7 padding', () {
      var inp = fromHex(
          '1FAF5E6B855A8F48A38BA6F0C68260EF22CA50E3E00D9F567149F7D66E8981E5');
      var key = 'abcdefghijklmnopqrstuvwx'.codeUnits;
      var salt = 'lka9JLKasljkdPsd'.codeUnits;
      var expected = 'A not very secret message';
      var actual = AES(key).cbc(salt).decrypt(inp);
      expect(String.fromCharCodes(actual), equals(expected));
    });
    test('256-bit with PKCS#7 padding', () {
      var inp = fromHex(
          '55D9375493876E2DE608BFFDE6AFF486A4FF0671B84BB39A0A62D8312D5B631A');
      var key = 'abcdefghijklmnopqrstuvwxyz012345'.codeUnits;
      var salt = 'lka9JLKasljkdPsd'.codeUnits;
      var expected = 'A not very secret message';
      var actual = AES(key).cbc(salt).decrypt(inp);
      expect(String.fromCharCodes(actual), equals(expected));
    });
  });

  group('encryption <-> decryption', () {
    test("128-bit", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).cbc(iv).encrypt(inp);
        var plain = AES(key).cbc(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("192-bit", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).cbc(iv).encrypt(inp);
        var plain = AES(key).cbc(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("256-bit", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).cbc(iv).encrypt(inp);
        var plain = AES(key).cbc(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
  });

  group('sink test', () {
    test('encryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = randomBytes(16);
        final aes = AES(key).cbc(iv);

        var input = randomBytes(j);
        var cipher = aes.encrypt(input);

        var enc = aes.encryptor.createSink();
        var output = <int>[];
        for (int i = 0; i < input.length; i += 23) {
          output.addAll(enc.add(input.skip(i).take(23).toList()));
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
        final aes = AES(key).cbc(iv);

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
  });

  test('reset salt', () {
    var iv = randomBytes(16);
    var key = randomBytes(24);
    var aes = AES(key).cbc(iv);
    for (int j = 0; j < 100; j++) {
      aes.resetIV();
      var inp = randomBytes(j);
      var cipher = aes.encrypt(inp);
      var plain = aes.decrypt(cipher);
      expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
    }
  });
}
