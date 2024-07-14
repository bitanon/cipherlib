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
    group('F2.1 CBC-AES128', () {
      var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
      var iv = fromHex('000102030405060708090a0b0c0d0e0f');
      var plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef'
        'f69f2445df4f9b17ad2b417be66c3710',
      );
      var cipher = fromHex(
        '7649abac8119b246cee98e9b12e9197d'
        '5086cb9b507219ee95db113a917678b2'
        '73bed6b8e3c1743b7116e69e22229516'
        '3ff1caa1681fac09120eca307586e1a7',
      );
      var aes = AES.noPadding(key).cbc(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F2.3 CBC-AES192', () {
      var key = fromHex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b');
      var iv = fromHex('000102030405060708090a0b0c0d0e0f');
      var plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef'
        'f69f2445df4f9b17ad2b417be66c3710',
      );
      var cipher = fromHex(
        '4f021db243bc633d7178183a9fa071e8'
        'b4d9ada9ad7dedf4e5e738763f69145a'
        '571b242012fb7ae07fa9baac3df102e0'
        '08b0e27988598881d920a9e64f5615cd',
      );
      var aes = AES.noPadding(key).cbc(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F2.5 CBC-AES256', () {
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
        'f58c4c04d6e5f1ba779eabfb5f7bfbd6'
        '9cfc4e967edb808d679f777bc6702c7d'
        '39f23369a9d9bacfa530e26304231461'
        'b2eb05e2c39be9fcda6c19078c6a9d1b',
      );
      var aes = AES.noPadding(key).cbc(iv);
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

  test('throws error on invalid input size', () {
    var aes = AES.noPadding(Uint8List(16)).cbc(Uint8List(16));
    expect(() => aes.encrypt(Uint8List(10)), throwsStateError);
    expect(() => aes.decrypt(Uint8List(10)), throwsStateError);
  });
  test('throws error on invalid salt size', () {
    var aes = AES(Uint8List(16));
    expect(() => aes.cbc(Uint8List(15)).encrypt([0]), throwsStateError);
    expect(() => aes.cbc(Uint8List(8)).decrypt([0]), throwsStateError);
  });

  group('empty message', () {
    var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
    var iv = fromHex('000102030405060708090a0b0c0d0e0f');
    var plain = Uint8List(0);
    var cipher = Uint8List(0);
    var aes = AES.noPadding(key).cbc(iv);
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
    var cipher = fromHex('a727b3bfaec6ed7521595fb326cdf5ca');
    var aes = AES(key).cbc(iv);
    test('encrypt', () {
      var actual = aes.encrypt(plain);
      expect(toHex(actual), equals(toHex(cipher)));
    });
    test('decrypt', () {
      var reverse = aes.decrypt(cipher);
      expect(toHex(reverse), equals(toHex(plain)));
    });
  });

  group("PKCS#7 padding", () {
    group('AES128', () {
      var key = 'abcdefghijklmnop'.codeUnits;
      var iv = 'lka9JLKasljkdPsd'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
          '07FD872F06478F991FFFCA2C649F4D5C1C7F769E4001541ACCF97639B9C8D750');
      var aes = AES.pkcs7(key).cbc(iv);
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
      var iv = 'lka9JLKasljkdPsd'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
          '1FAF5E6B855A8F48A38BA6F0C68260EF22CA50E3E00D9F567149F7D66E8981E5');
      var aes = AES.pkcs7(key).cbc(iv);
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
      var iv = 'lka9JLKasljkdPsd'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
          '55D9375493876E2DE608BFFDE6AFF486A4FF0671B84BB39A0A62D8312D5B631A');
      var aes = AES.pkcs7(key).cbc(iv);
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
    test('encryption + decryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = randomBytes(16);
        var input = randomBytes(j);

        final aes = AES(key).cbc(iv);
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
