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
    group('F3.7 CFB8-AES128.Encrypt', () {
      var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
      var iv = fromHex('000102030405060708090a0b0c0d0e0f');
      var plain = fromHex('6bc1bee22e409f96e93d7e117393172aae2d');
      var cipher = fromHex('3b79424c9c0dd436bace9e0ed4586a4f32b9');
      var aes = AES(key).cfb8(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F3.9 CFB8-AES192.Encrypt', () {
      var key = fromHex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b');
      var iv = fromHex('000102030405060708090a0b0c0d0e0f');
      var plain = fromHex('6bc1bee22e409f96e93d7e117393172aae2d');
      var cipher = fromHex('cda2521ef0a905ca44cd057cbf0d47a0678a');
      var aes = AES(key).cfb8(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F3.11 CFB8-AES256.Encrypt', () {
      var key = fromHex(
        '603deb1015ca71be2b73aef0857d7781'
        '1f352c073b6108d72d9810a30914dff4',
      );
      var iv = fromHex('000102030405060708090a0b0c0d0e0f');
      var plain = fromHex('6bc1bee22e409f96e93d7e117393172aae2d');
      var cipher = fromHex('dc1f1a8520a64db55fcc8ac554844e889700');
      var aes = AES(key).cfb8(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F3.13 CFB128-AES128.Encrypt', () {
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
        'c8a64537a0b3a93fcde3cdad9f1ce58b'
        '26751f67a3cbb140b1808cf187a4f4df'
        'c04b05357c5d1c0eeac4c66f9ff7f2e6',
      );
      var aes = AES(key).cfb(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F3.15 CFB128-AES192.Encrypt', () {
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
        '67ce7f7f81173621961a2b70171d3d7a'
        '2e1e8a1dd59b88b1c8e60fed1efac4c9'
        'c05f9f9ca9834fa042ae8fba584b09ff',
      );
      var aes = AES(key).cfb(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F3.17 CFB128-AES256.Encrypt', () {
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
        '39ffed143b28b1c832113c6331e5407b'
        'df10132415e54b92a13ed0a8267ae2f9'
        '75a385741ab9cef82031623d55b1e471',
      );
      var aes = AES(key).cfb(iv);
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

  group('CFB64-AES128', () {
    group('single block', () {
      var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
      var iv = fromHex('000102030405060708090a0b0c0d0e0f');
      var plain = fromHex(
        '6bc1bee22e409f96',
      );
      var cipher = fromHex(
        '3b3fd92eb72dad20',
      );
      var aes = AES(key).cfb64(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('multi block', () {
      var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
      var iv = fromHex('000102030405060708090a0b0c0d0e0f');
      var plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a',
      );
      var cipher = fromHex(
        '3b3fd92eb72dad20764bc8b40ee0de40',
      );
      var aes = AES(key).cfb64(iv);
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

  test('throws error on invalid salt size', () {
    var aes = AES(Uint8List(16));
    expect(() => aes.cfb(Uint8List(15)).encrypt([0]), throwsStateError);
    expect(() => aes.cfb(Uint8List(8)).decrypt([0]), throwsStateError);
  });

  group('empty message', () {
    var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
    var iv = fromHex('000102030405060708090a0b0c0d0e0f');
    var plain = Uint8List(0);
    var cipher = Uint8List(0);
    var aes = AES(key).cfb(iv);
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
    var plain = fromHex(
      '6bc1',
    );
    var cipher = fromHex(
      '3b3f',
    );
    var aes = AES(key).cfb(iv);
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
      var cipher = fromBase64('tEUQSPkqjLK6MZkW7O9DujeXuxsUiJtfyA==');
      var aes = AES.pkcs7(key).cfb(iv);
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
      var cipher = fromBase64('umoiqsbvbhRFB+FVYdGjuwfCo5rQFz/uQw==');
      var aes = AES.pkcs7(key).cfb(iv);
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
      var cipher = fromBase64('gQOajlfwdgmrSB/mIVYUl1zCxL6F050zRw==');
      var aes = AES.pkcs7(key).cfb(iv);
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
    test("AES128/CFB", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).cfb(iv).encrypt(inp);
        var plain = AES(key).cfb(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES192/CFB", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).cfb(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES256/CFB", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).cfb(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });

    test("AES128/CFB-8", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).cfb8(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES192/CFB-8", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).cfb8(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES256/CFB-8", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).cfb8(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });

    test("AES128/CFB-64", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).cfb64(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES192/CFB-64", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).cfb64(iv);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES256/CFB-64", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var aes = AES(key).cfb64(iv);
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
        final aes = AES(key).cfb64(iv);

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
        final aes = AES(key).cfb(iv);

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

        final aes = AES(key).cfb8(iv);
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
    var aes = AES(key).cfb(iv);
    for (int j = 0; j < 100; j++) {
      aes.resetIV();
      var inp = randomBytes(j);
      var cipher = aes.encrypt(inp);
      var plain = aes.decrypt(cipher);
      expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
    }
  });
}
