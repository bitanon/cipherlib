// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/codecs.dart';
import 'package:hashlib/hashlib.dart';
import 'package:test/test.dart';

void main() {
  group("functionality tests", () {
    final key = Uint8List(32);
    final iv = Uint8List(16);
    final input = Uint8List(64);
    test("name is correct", () {
      expect(AES(key).ctr(iv).name, "AES/CTR/NoPadding");
    });
    test("accepts null IV", () {
      AESInCTRMode(key).encrypt(input);
    });
    test("encryptor and decryptor is the same", () {
      var aes = AES(key).ctr(iv);
      expect(aes.encryptor, aes.decryptor);
    });
    test("encryptor name is correct", () {
      expect(AES(key).ctr(iv).encryptor.name, "AES#cipher/CTR/NoPadding");
    });
    test("decryptor name is correct", () {
      expect(AES(key).ctr(iv).decryptor.name, "AES#cipher/CTR/NoPadding");
    });
    test('throws error on invalid salt size', () {
      var aes = AES(Uint8List(16));
      expect(() => aes.ctr(Uint8List(15)).encrypt([0]), throwsStateError);
      expect(() => aes.ctr(Uint8List(8)).decrypt([0]), throwsStateError);
    });
    test('sink test (no add after close)', () {
      final aes = AES(key).ctr(iv);
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
    test('reset iv', () {
      var iv = randomBytes(16);
      var key = randomBytes(24);
      var aes = AES(key).ctr(iv);
      for (int j = 0; j < 100; j++) {
        aes.resetIV();
        var inp = randomBytes(j);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
  });

  group('empty message', () {
    var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
    var iv = fromHex('000102030405060708090a0b0c0d0e0f');
    var plain = Uint8List(0);
    var cipher = Uint8List(0);
    var aes = AES(key).ctr(iv);
    test('encrypt', () {
      var actual = aes.encrypt(plain);
      expect(toHex(actual), equals(toHex(cipher)));
    });
    test('decrypt', () {
      var reverse = aes.decrypt(cipher);
      expect(toHex(reverse), equals(toHex(plain)));
    });
  });

  // https://csrc.nist.gov/pubs/sp/800/38/a/final
  group('NIST SP 800-38A', () {
    group('F5.1 CTR-AES128.Encrypt', () {
      var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
      var iv = fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
      var plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef'
        'f69f2445df4f9b17ad2b417be66c3710',
      );
      var cipher = fromHex(
        '874d6191b620e3261bef6864990db6ce'
        '9806f66b7970fdff8617187bb9fffdff'
        '5ae4df3edbd5d35e5b4f09020db03eab'
        '1e031dda2fbe03d1792170a0f3009cee',
      );
      var aes = AES.noPadding(key).ctr(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F5.3 CTR-AES192.Encrypt', () {
      var key = fromHex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b');
      var iv = fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
      var plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef'
        'f69f2445df4f9b17ad2b417be66c3710',
      );
      var cipher = fromHex(
        '1abc932417521ca24f2b0459fe7e6e0b'
        '090339ec0aa6faefd5ccc2c6f4ce8e94'
        '1e36b26bd1ebc670d1bd1d665620abf7'
        '4f78a7f6d29809585a97daec58c6b050',
      );
      var aes = AES.noPadding(key).ctr(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F5.5 CTR-AES256.Encrypt', () {
      var key = fromHex(
        '603deb1015ca71be2b73aef0857d7781'
        '1f352c073b6108d72d9810a30914dff4',
      );
      var iv = fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
      var plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef'
        'f69f2445df4f9b17ad2b417be66c3710',
      );
      var cipher = fromHex(
        '601ec313775789a5b7a7f504bbf3d228'
        'f443e3ca4d62b59aca84e990cacaf5c5'
        '2b0930daa23de94ce87017ba2d84988d'
        'dfc9c58db67aada613c2dd08457941a6',
      );
      var aes = AES.noPadding(key).ctr(iv);
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

  group('non block', () {
    var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
    var iv = fromHex('000102030405060708090a0b0c0d0e0f');
    var plain = fromHex('6bc1');
    var cipher = fromHex('3b3f');
    var aes = AES(key).ctr(iv);
    test('encrypt', () {
      var actual = aes.encrypt(plain);
      expect(toHex(actual), equals(toHex(cipher)));
    });
    test('decrypt', () {
      var reverse = aes.decrypt(cipher);
      expect(toHex(reverse), equals(toHex(plain)));
    });
  });

  group('treats counter as 64-bit number', () {
    test('increment from maximum 32-bit integer', () {
      var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
      var plain1 = randomBytes(16);
      var plain2 = randomBytes(16);
      var plain3 = randomBytes(16);

      var iv1 = fromHex('000102030405060708090a00ffffffff');
      var sink1 = AESInCTRModeSink(key, iv1);
      sink1.add(plain1);
      var out1 = sink1.add(plain2);
      var out3 = sink1.add(plain3);

      var iv2 = fromHex('000102030405060708090a0100000000');
      var sink2 = AESInCTRModeSink(key, iv2);
      var out2 = sink2.add(plain2);

      var iv3 = fromHex('000102030405060708090a0100000001');
      var sink3 = AESInCTRModeSink(key, iv3);
      var out4 = sink3.add(plain3);

      expect(toHex(out1), equals(toHex(out2)));
      expect(toHex(out3), equals(toHex(out4)));
    });

    test('increment from maximum 64-bit integer', () {
      var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
      var plain1 = randomBytes(16);
      var plain2 = randomBytes(16);
      var plain3 = randomBytes(16);

      var iv1 = fromHex('0001020304050607ffffffffffffffff');
      var sink1 = AESInCTRModeSink(key, iv1);
      sink1.add(plain1);
      var out1 = sink1.add(plain2);
      var out3 = sink1.add(plain3);

      var iv2 = fromHex('00010203040506070000000000000000');
      var sink2 = AESInCTRModeSink(key, iv2);
      var out2 = sink2.add(plain2);

      var iv3 = fromHex('00010203040506070000000000000001');
      var sink3 = AESInCTRModeSink(key, iv3);
      var out4 = sink3.add(plain3);

      expect(toHex(out1), equals(toHex(out2)));
      expect(toHex(out3), equals(toHex(out4)));
    });
  });

  group("PKCS#7 padding", () {
    group('AES128', () {
      var key = 'abcdefghijklmnop'.codeUnits;
      var iv = 'lka9JLKasljkdPsd'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher =
          fromHex('047B37EBDE11A491CB3F7842E48E54F8326E293619E69BE24B');
      var aes = AES.pkcs7(key).ctr(iv);
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
      var cipher =
          fromHex('A85734374F88C90877C39D7A4C78177F5F80290F7E2F4B4B15');
      var aes = AES.pkcs7(key).ctr(iv);
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
      var cipher =
          fromHex('05A2F1FF79461F903C9E9DE82FF710244D36E35AF3AA8B6695');
      var aes = AES.pkcs7(key).ctr(iv);
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
        var cipher = AES(key).ctr(iv).encrypt(inp);
        var plain = AES(key).ctr(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("192-bit", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).ctr(iv).encrypt(inp);
        var plain = AES(key).ctr(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("256-bit", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).ctr(iv).encrypt(inp);
        var plain = AES(key).ctr(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("with nonce and counter", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var nonce = Nonce64.random();
        var aes = AESInCTRMode.nonce(key, nonce: nonce);
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
        final aes = AES(key).ctr(iv);

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
        final aes = AES(key).ctr(iv);

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

        final aes = AES(key).ctr(iv);
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
}
