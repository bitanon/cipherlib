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
    final input = Uint8List(64);
    test("name is correct", () {
      expect(AES.noPadding(key).ecb().name, "AES/ECB/NoPadding");
      expect(AES.ansi(key).ecb().name, "AES/ECB/ANSI");
      expect(AES.byte(key).ecb().name, "AES/ECB/Byte");
      expect(AES.pkcs7(key).ecb().name, "AES/ECB/PKCS7");
    });
    test("padding is correct", () {
      expect(AES.noPadding(key).ecb().padding, Padding.none);
      expect(AES.ansi(key).ecb().padding, Padding.ansi);
      expect(AES.byte(key).ecb().padding, Padding.byte);
      expect(AES.pkcs7(key).ecb().padding, Padding.pkcs7);
    });
    test("accepts null IV", () {
      AESInECBMode(key).encrypt(input);
    });
    test("encryptor name is correct", () {
      expect(
          AES.noPadding(key).ecb().encryptor.name, "AES#encrypt/ECB/NoPadding");
      expect(AES.ansi(key).ecb().encryptor.name, "AES#encrypt/ECB/ANSI");
      expect(AES.byte(key).ecb().encryptor.name, "AES#encrypt/ECB/Byte");
      expect(AES.pkcs7(key).ecb().encryptor.name, "AES#encrypt/ECB/PKCS7");
    });
    test("decryptor name is correct", () {
      expect(
          AES.noPadding(key).ecb().decryptor.name, "AES#decrypt/ECB/NoPadding");
      expect(AES.ansi(key).ecb().decryptor.name, "AES#decrypt/ECB/ANSI");
      expect(AES.byte(key).ecb().decryptor.name, "AES#decrypt/ECB/Byte");
      expect(AES.pkcs7(key).ecb().decryptor.name, "AES#decrypt/ECB/PKCS7");
    });
    test('encryptor sink test (no add after close)', () {
      final aes = AES.noPadding(key).ecb();
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
      final aes = AES.noPadding(key).ecb();
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
  });

  // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
  group("NIST.FIPS.197-upd1 AES128", () {
    var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
    var plain = fromHex('3243f6a8885a308d313198a2e0370734');
    var cipher = fromHex('3925841d02dc09fbdc118597196a0b32');
    var aes = AES.noPadding(key).ecb();
    test('encrypt', () {
      var actual = aes.encrypt(plain);
      expect(toHex(actual), equals(toHex(cipher)));
    });
    test('decrypt', () {
      var reverse = aes.decrypt(cipher);
      expect(toHex(reverse), equals(toHex(plain)));
    });
  });
  group('NIST SP 800-38A', () {
    // https://csrc.nist.gov/pubs/sp/800/38/a/final
    group('F2.1 ECB-AES128', () {
      var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
      var plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef'
        'f69f2445df4f9b17ad2b417be66c3710',
      );
      var cipher = fromHex(
        '3ad77bb40d7a3660a89ecaf32466ef97'
        'f5d3d58503b9699de785895a96fdbaaf'
        '43b1cd7f598ece23881b00e3ed030688'
        '7b0c785e27e8ad3f8223207104725dd4',
      );
      var aes = AES.noPadding(key).ecb();
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F2.3 ECB-AES192', () {
      var key = fromHex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b');
      var plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef'
        'f69f2445df4f9b17ad2b417be66c3710',
      );
      var cipher = fromHex(
        'bd334f1d6e45f25ff712a214571fa5cc'
        '974104846d0ad3ad7734ecb3ecee4eef'
        'ef7afd2270e2e60adce0ba2face6444e'
        '9a4b41ba738d6c72fb16691603c18e0e',
      );
      var aes = AES.noPadding(key).ecb();
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('F2.5 ECB-AES256', () {
      var key = fromHex(
        '603deb1015ca71be2b73aef0857d7781'
        '1f352c073b6108d72d9810a30914dff4',
      );
      var plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef'
        'f69f2445df4f9b17ad2b417be66c3710',
      );
      var cipher = fromHex(
        'f3eed1bdb5d2a03c064b5a7e3db181f8'
        '591ccb10d410ed26dc5ba74a31362870'
        'b6ed21b99ca6f4f9f153e7b1beafed1d'
        '23304b7a39f9f3ff067d8d8f9e24ecc7',
      );
      var aes = AES.noPadding(key).ecb();
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
    var aes = AES.noPadding(Uint8List(16)).ecb();
    expect(() => aes.encrypt(Uint8List(10)), throwsStateError);
    expect(() => aes.decrypt(Uint8List(10)), throwsStateError);
    expect(() => aes.encrypt(Uint8List(17)), throwsStateError);
    expect(() => aes.decrypt(Uint8List(17)), throwsStateError);
  });

  group('empty message', () {
    var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
    var plain = Uint8List(0);
    var cipher = Uint8List(0);
    var aes = AES.noPadding(key).ecb();
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
    var plain = fromHex('6bc1');
    var cipher = fromHex('3dd9b756926018faf1fe43ab6545256c');
    var aes = AES(key).ecb();
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
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
          '9224d7a1b18964d1184f5e93b0ebebd2a26031ef0e1c7f271298cbec4351abe8');
      var aes = AES.pkcs7(key).ecb();
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
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
          '4520a2df64b588535d95d14625fe6f66e36c07bfb712b1f1dbf9e88f9c4ec2db');
      var aes = AES.pkcs7(key).ecb();
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
      var cipher = fromHex(
          '09f1ff0aeb92b79274ac55abdc074a0198e1a6fb59c3177fb56ed1d75bc424e3');
      var aes = AES.pkcs7(key).ecb();
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
        var input = randomBytes(j);
        var bytes = Uint8List.fromList(input);
        var cipher = AES(key).ecb().encrypt(input);
        var plain = AES(key).ecb().decrypt(cipher);
        expect(toHex(bytes), equals(toHex(plain)), reason: '[size: $j]');
      }
    });
    test("192-bit", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var input = randomBytes(j);
        var bytes = Uint8List.fromList(input);
        var cipher = AES(key).ecb().encrypt(input);
        var plain = AES(key).ecb().decrypt(cipher);
        expect(toHex(bytes), equals(toHex(plain)), reason: '[size: $j]');
      }
    });
    test("256-bit", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var input = randomBytes(j);
        var bytes = Uint8List.fromList(input);
        var cipher = AES(key).ecb().encrypt(input);
        var plain = AES(key).ecb().decrypt(cipher);
        expect(toHex(bytes), equals(toHex(plain)), reason: '[size: $j]');
      }
    });
  });

  group('sink test', () {
    test('encryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        final aes = AES(key).ecb();

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
        var input = randomBytes(j);
        var cipher = AES(key).ecb().encrypt(input);

        var dec = AES(key).ecb().decryptor.createSink();
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
        var input = randomBytes(j);

        final aes = AES(key).ecb();
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
