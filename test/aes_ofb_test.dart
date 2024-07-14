// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/hashlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

void main() {
  group('NIST SP 800-38A', () {
    // https://csrc.nist.gov/pubs/sp/800/38/a/final
    group('F4.1 CBC-AES128.Encrypt', () {
      var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
      var iv = fromHex('000102030405060708090a0b0c0d0e0f');
      var plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef'
        'f69f2445df4f9b17ad2b417be66c3710',
      );
      var cipher = fromHex(
        '3b3fd92eb72dad20333449f8e83cfb4a'
        '7789508d16918f03f53c52dac54ed825'
        '9740051e9c5fecf64344f7a82260edcc'
        '304c6528f659c77866a510d9c1d6ae5e',
      );
      test('encryption', () {
        var actual = AES(key).ofb(iv).encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decryption', () {
        var reverse = AES(key).ofb(iv).decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F4.3 CBC-AES192.Encrypt', () {
      var key = fromHex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b');
      var iv = fromHex('000102030405060708090a0b0c0d0e0f');
      var plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef'
        'f69f2445df4f9b17ad2b417be66c3710',
      );
      var cipher = fromHex(
        'cdc80d6fddf18cab34c25909c99a4174'
        'fcc28b8d4c63837c09e81700c1100401'
        '8d9a9aeac0f6596f559c6d4daf59a5f2'
        '6d9f200857ca6c3e9cac524bd9acc92a',
      );
      test('encryption', () {
        var actual = AES(key).ofb(iv).encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decryption', () {
        var reverse = AES(key).ofb(iv).decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F4.5 CBC-AES256.Encrypt', () {
      var key = fromHex(
        '603deb1015ca71be2b73aef0857d7781'
        '1f352c073b6108d72d9810a30914dff4',
      );
      var iv = fromHex('000102030405060708090a0b0c0d0e0f');
      var plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef'
        'f69f2445df4f9b17ad2b417be66c3710',
      );
      var cipher = fromHex(
        'dc7e84bfda79164b7ecd8486985d3860'
        '4febdc6740d20b3ac88f6ad82a4fb08d'
        '71ab47a086e86eedf39d1c5bba97c408'
        '0126141d67f37be8538f5a8be740e484',
      );
      test('encryption', () {
        var actual = AES(key).ofb(iv).encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decryption', () {
        var reverse = AES(key).ofb(iv).decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
  });

  test('throws error on invalid salt size', () {
    var aes = AES(Uint8List(16));
    expect(() => aes.ofb(Uint8List(15)).encrypt([0]), throwsStateError);
    expect(() => aes.ofb(Uint8List(8)).decrypt([0]), throwsStateError);
  });

  group('empty message', () {
    var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
    var iv = fromHex('000102030405060708090a0b0c0d0e0f');
    var plain = Uint8List(0);
    var cipher = Uint8List(0);
    var aes = AES(key).ofb(iv);
    test('encrypt', () {
      var actual = aes.encrypt(plain);
      expect(toHex(actual), equals(toHex(cipher)));
    });
    test('decrypt', () {
      var reverse = aes.decrypt(cipher);
      expect(toHex(reverse), equals(toHex(plain)));
    });
  });

  group('non block', () {
    var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
    var iv = fromHex('000102030405060708090a0b0c0d0e0f');
    var plain = fromHex('6bc1');
    var cipher = fromHex('3b3f');
    var aes = AES(key).ofb(iv);
    test('encrypt', () {
      var actual = aes.encrypt(plain);
      expect(toHex(actual), equals(toHex(cipher)));
    });
    test('decrypt', () {
      var reverse = aes.decrypt(cipher);
      expect(toHex(reverse), equals(toHex(plain)));
    });
  });

  group("Zero IV", () {
    group('AES128', () {
      var key = 'abcdefghijklmnop'.codeUnits;
      var iv = Uint8List(16);
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromBase64('tEUQSPkqjLK6MZkW7O9DuhzVOQWbL5OPWg==');
      var aes = AES.pkcs7(key).ofb(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('AES192', () {
      var key = 'abcdefghijklmnopqrstuvwx'.codeUnits;
      var iv = Uint8List(16);
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromBase64('umoiqsbvbhRFB+FVYdGju6c2xItTtn1qmA==');
      var aes = AES.pkcs7(key).ofb(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('AES256', () {
      var key = 'abcdefghijklmnopqrstuvwxyz012345'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var iv = Uint8List(16);
      var cipher = fromBase64('gQOajlfwdgmrSB/mIVYUl6vcinEjJLLfdQ==');
      var aes = AES.pkcs7(key).ofb(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
  });

  group('encryption <-> decryption', () {
    test("AES128/OFB", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).ofb(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES192/OFB", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).ofb(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES256/OFB", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).ofb(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });

    test("AES128/OFB-8", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).ofb8(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES192/OFB-8", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).ofb8(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES256/OFB-8", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).ofb8(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });

    test("AES128/OFB-64", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).ofb64(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES192/OFB-64", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).ofb64(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES256/OFB-64", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).ofb64(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
  });

  group('sink test', () {
    test('encryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = randomBytes(16);
        final aes = AES(key).ofb64(iv);

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
        final aes = AES(key).ofb(iv);

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

        final aes = AES(key).ofb8(iv);
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
    var aes = AES(key).ofb(iv);
    for (int j = 0; j < 100; j++) {
      aes.resetIV();
      var inp = randomBytes(j);
      var cipher = aes.encrypt(inp);
      var plain = aes.decrypt(cipher);
      expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
    }
  });
}
