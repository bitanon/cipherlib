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
    // https://www.ibm.com/docs/en/linux-on-systems?topic=examples-aes-ofb-mode-example
    group('OFB data - 1 for AES128', () {
      var key = Uint8List.fromList([
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, //
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
      ]);
      var iv = Uint8List.fromList([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]);
      var expectedIV = Uint8List.fromList([
        0x50, 0xfe, 0x67, 0xcc, 0x99, 0x6d, 0x32, 0xb6, //
        0xda, 0x09, 0x37, 0xe9, 0x9b, 0xaf, 0xec, 0x60,
      ]);
      var data = Uint8List.fromList([
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, //
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
      ]);
      var expected = Uint8List.fromList([
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, //
        0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
      ]);
      test('IV', () {
        var actualIV = AES(key).ofb(iv).encrypt(Uint8List(iv.length));
        expect(toHex(actualIV), equals(toHex(expectedIV)));
      });
      test('encryption', () {
        var actual = AES(key).ofb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decryption', () {
        var reverse = AES(key).ofb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('OFB data - 2 for AES128', () {
      var key = Uint8List.fromList([
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, //
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
      ]);
      var iv = Uint8List.fromList([
        0x50, 0xfe, 0x67, 0xcc, 0x99, 0x6d, 0x32, 0xb6, //
        0xda, 0x09, 0x37, 0xe9, 0x9b, 0xaf, 0xec, 0x60,
      ]);
      var expectedIV = Uint8List.fromList([
        0xd9, 0xa4, 0xda, 0xda, 0x08, 0x92, 0x23, 0x9f, //
        0x6b, 0x8b, 0x3d, 0x76, 0x80, 0xe1, 0x56, 0x74,
      ]);
      var data = Uint8List.fromList([
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, //
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
      ]);
      var expected = Uint8List.fromList([
        0x77, 0x89, 0x50, 0x8d, 0x16, 0x91, 0x8f, 0x03, //
        0xf5, 0x3c, 0x52, 0xda, 0xc5, 0x4e, 0xd8, 0x25,
      ]);
      test('IV', () {
        var actualIV = AES(key).ofb(iv).encrypt(Uint8List(iv.length));
        expect(toHex(actualIV), equals(toHex(expectedIV)));
      });
      test('encryption', () {
        var actual = AES(key).ofb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decryption', () {
        var reverse = AES(key).ofb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('OFB data - 3 for AES192', () {
      var key = Uint8List.fromList([
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, //
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
      ]);
      var iv = Uint8List.fromList([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]);
      var expectedIV = Uint8List.fromList([
        0xa6, 0x09, 0xb3, 0x8d, 0xf3, 0xb1, 0x13, 0x3d, //
        0xdd, 0xff, 0x27, 0x18, 0xba, 0x09, 0x56, 0x5e,
      ]);
      var data = Uint8List.fromList([
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, //
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
      ]);
      var expected = Uint8List.fromList([
        0xcd, 0xc8, 0x0d, 0x6f, 0xdd, 0xf1, 0x8c, 0xab, //
        0x34, 0xc2, 0x59, 0x09, 0xc9, 0x9a, 0x41, 0x74,
      ]);
      test('IV', () {
        var actualIV = AES(key).ofb(iv).encrypt(Uint8List(iv.length));
        expect(toHex(actualIV), equals(toHex(expectedIV)));
      });
      test('encryption', () {
        var actual = AES(key).ofb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decryption', () {
        var reverse = AES(key).ofb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('OFB data - 4 for AES192', () {
      var key = Uint8List.fromList([
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, //
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
      ]);
      var iv = Uint8List.fromList([
        0xa6, 0x09, 0xb3, 0x8d, 0xf3, 0xb1, 0x13, 0x3d, //
        0xdd, 0xff, 0x27, 0x18, 0xba, 0x09, 0x56, 0x5e,
      ]);
      var expectedIV = Uint8List.fromList([
        0x52, 0xef, 0x01, 0xda, 0x52, 0x60, 0x2f, 0xe0, //
        0x97, 0x5f, 0x78, 0xac, 0x84, 0xbf, 0x8a, 0x50,
      ]);
      var data = Uint8List.fromList([
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, //
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
      ]);
      var expected = Uint8List.fromList([
        0xfc, 0xc2, 0x8b, 0x8d, 0x4c, 0x63, 0x83, 0x7c, //
        0x09, 0xe8, 0x17, 0x00, 0xc1, 0x10, 0x04, 0x01,
      ]);
      test('IV', () {
        var actualIV = AES(key).ofb(iv).encrypt(Uint8List(iv.length));
        expect(toHex(actualIV), equals(toHex(expectedIV)));
      });
      test('encryption', () {
        var actual = AES(key).ofb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decryption', () {
        var reverse = AES(key).ofb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('OFB data - 5 for AES256', () {
      var key = Uint8List.fromList([
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, //
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
      ]);
      var iv = Uint8List.fromList([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]);
      var expectedIV = Uint8List.fromList([
        0xb7, 0xbf, 0x3a, 0x5d, 0xf4, 0x39, 0x89, 0xdd, //
        0x97, 0xf0, 0xfa, 0x97, 0xeb, 0xce, 0x2f, 0x4a,
      ]);
      var data = Uint8List.fromList([
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, //
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
      ]);
      var expected = Uint8List.fromList([
        0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b, //
        0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
      ]);
      test('IV', () {
        var actualIV = AES(key).ofb(iv).encrypt(Uint8List(iv.length));
        expect(toHex(actualIV), equals(toHex(expectedIV)));
      });
      test('encryption', () {
        var actual = AES(key).ofb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decryption', () {
        var reverse = AES(key).ofb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('OFB data - 6 for AES256', () {
      var key = Uint8List.fromList([
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, //
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
      ]);
      var iv = Uint8List.fromList([
        0xb7, 0xbf, 0x3a, 0x5d, 0xf4, 0x39, 0x89, 0xdd, //
        0x97, 0xf0, 0xfa, 0x97, 0xeb, 0xce, 0x2f, 0x4a,
      ]);
      var expectedIV = Uint8List.fromList([
        0xe1, 0xc6, 0x56, 0x30, 0x5e, 0xd1, 0xa7, 0xa6, //
        0x56, 0x38, 0x05, 0x74, 0x6f, 0xe0, 0x3e, 0xdc,
      ]);
      var data = Uint8List.fromList([
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, //
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
      ]);
      var expected = Uint8List.fromList([
        0x4f, 0xeb, 0xdc, 0x67, 0x40, 0xd2, 0x0b, 0x3a, //
        0xc8, 0x8f, 0x6a, 0xd8, 0x2a, 0x4f, 0xb0, 0x8d,
      ]);
      test('IV', () {
        var actualIV = AES(key).ofb(iv).encrypt(Uint8List(iv.length));
        expect(toHex(actualIV), equals(toHex(expectedIV)));
      });
      test('encryption', () {
        var actual = AES(key).ofb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decryption', () {
        var reverse = AES(key).ofb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
  });

  test('throws error on invalid salt size', () {
    var aes = AES(Uint8List(16));
    expect(() => aes.ofb(Uint8List(15)).encrypt([0]), throwsStateError);
    expect(() => aes.ofb(Uint8List(8)).decrypt([0]), throwsStateError);
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
        var cipher = AES(key).ofb(iv).encrypt(inp);
        var plain = AES(key).ofb(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES192/OFB", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).ofb(iv).encrypt(inp);
        var plain = AES(key).ofb(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES256/OFB", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).ofb(iv).encrypt(inp);
        var plain = AES(key).ofb(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
  });

  group('sink test', () {
    test('encryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = randomBytes(16);
        final aes = AES(key).ofb(iv);

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
