// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:hashlib/random.dart';
import 'package:test/test.dart';

void main() {
  group('validation', () {
    test('name', () {
      expect(Salsa20(Uint8List(32)).name, "Salsa20");
    });
    test('accepts empty message', () {
      var key = randomNumbers(32);
      var nonce = randomBytes(16);
      expect(salsa20([], key, nonce: nonce), equals([]));
    });
    test('The key should be either 16 or 32 bytes', () {
      for (int i = 0; i < 100; ++i) {
        void cb() => Salsa20(Uint8List(i));
        if (i == 16 || i == 32) {
          expect(() => cb(), returnsNormally, reason: 'length: $i');
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('The nonce should be either 8, or 16 bytes', () {
      var key = Uint8List(32);
      for (int i = 0; i < 100; ++i) {
        void cb() => Salsa20(key, Uint8List(i));
        if (i == 8 || i == 16) {
          expect(() => cb(), returnsNormally, reason: 'length: $i');
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('Counter is not expected with 16-byte nonce', () {
      final key = Uint8List(32);
      final c = Nonce64.zero();
      expect(() => Salsa20(key, Uint8List(16), c), throwsArgumentError);
    });
    test('If counter is not provided, default counter is used', () {
      final key = Uint8List(32);
      final nonce = [1, 1, 1, 1, 1, 1, 1, 1];
      final algo = Salsa20(key, nonce);
      expect(algo.iv, equals([1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]));
    });
    test('Counter is set correctly when provided with 8-byte nonce', () {
      final key = Uint8List(32);
      final nonce = [1, 1, 1, 1, 1, 1, 1, 1];
      final counter = Nonce64.bytes([2, 2, 2, 2, 2, 2, 2, 2]);
      final algo = Salsa20(key, nonce, counter);
      expect(algo.iv, equals([1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2]));
    });
    test('random nonce is used if nonce is null, ', () {
      var key = randomNumbers(32);
      var text = randomBytes(100);
      salsa20(text, key);
    });
  });

  group('known inputs', () {
    test('Specification example (32-bytes key)', () {
      var key = [
        ...List.generate(16, (i) => i + 1),
        ...List.generate(16, (i) => i + 201),
      ];
      var nonce = List.generate(16, (i) => i + 101);
      var sample = Uint8List(64);
      var output = [
        69, 37, 68, 39, 41, 15, 107, 193, 255, 139, 122, 6, 170, 233, 217, //
        98, 89, 144, 182, 106, 21, 51, 200, 65, 239, 49, 222, 34, 215, 114, 40,
        126, 104, 197, 7, 225, 197, 153, 31, 2, 102, 78, 76, 176, 84, 245, 246,
        184, 177, 160, 133, 130, 6, 72, 149, 119, 192, 195, 132, 236, 234, 103,
        246, 74
      ];
      var cipher = salsa20(sample, key, nonce: nonce);
      expect(output, equals(cipher));
    });
    test('Specification example (16-bytes key)', () {
      var key = List.generate(16, (i) => i + 1);
      var nonce = List.generate(16, (i) => i + 101);
      var sample = Uint8List(64);
      var output = [
        39, 173, 46, 248, 30, 200, 82, 17, 48, 67, 254, 239, 37, 18, 13, //
        247, 241, 200, 61, 144, 10, 55, 50, 185, 6, 47, 246, 253, 143, 86, 187,
        225, 134, 85, 110, 246, 161, 163, 43, 235, 231, 94, 171, 51, 145, 214,
        112, 29, 14, 232, 5, 16, 151, 140, 183, 141, 171, 9, 122, 181, 104, 182,
        177, 193
      ];
      var cipher = salsa20(sample, key, nonce: nonce);
      expect(output, equals(cipher));
    });

    // https://github.com/golang/crypto/blob/master/salsa20/salsa20_test.go
    test('Go crypto test #1', () {
      final key = fromHex(
        '0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D',
      );
      final nonce = fromHex('0D74DB42A91077DE');
      final expectedXor = fromHex(
        'C349B6A51A3EC9B712EAED3F90D8BCEE69B7628645F251A996F55260C62EF31F'
        'D6C6B0AEA94E136C9D984AD2DF3578F78E457527B03A0450580DD874F63B1AB9',
      );

      final output = salsa20(Uint8List(131072), key, nonce: nonce);
      final blockXor = Uint8List(64);
      for (int i = 0; i < output.length; i += 64) {
        for (int j = 0; j < 64; ++j) {
          blockXor[j] ^= output[i + j];
        }
      }

      expect(blockXor, equals(expectedXor));
    });
    test('Go crypto test #2', () {
      final key = fromHex(
        '0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12',
      );
      final nonce = fromHex('167DE44BB21980E7');
      final expectedXor = fromHex(
        'C3EAAF32836BACE32D04E1124231EF47E101367D6305413A0EEB07C60698A287'
        '6E4D031870A739D6FFDDD208597AFF0A47AC17EDB0167DD67EBA84F1883D4DFD',
      );

      final output = salsa20(Uint8List(131072), key, nonce: nonce);
      final blockXor = Uint8List(64);
      for (int i = 0; i < output.length; i += 64) {
        for (int j = 0; j < 64; ++j) {
          blockXor[j] ^= output[i + j];
        }
      }

      expect(blockXor, equals(expectedXor));
    });
    test('Go crypto test #3', () {
      final key = fromHex(
        '0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417',
      );
      final nonce = fromHex('1F86ED54BB2289F0');
      final expectedXor = fromHex(
        '3CD23C3DC90201ACC0CF49B440B6C417F0DC8D8410A716D5314C059E14B1A8D9'
        'A9FB8EA3D9C8DAE12B21402F674AA95C67B1FC514E994C9D3F3A6E41DFF5BBA6',
      );

      final output = salsa20(Uint8List(131072), key, nonce: nonce);
      final blockXor = Uint8List(64);
      for (int i = 0; i < output.length; i += 64) {
        for (int j = 0; j < 64; ++j) {
          blockXor[j] ^= output[i + j];
        }
      }

      expect(blockXor, equals(expectedXor));
    });
    test('Go crypto test #4', () {
      final key = fromHex(
        '0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C',
      );
      final nonce = fromHex('288FF65DC42B92F9');
      final expectedXor = fromHex(
        'E00EBCCD70D69152725F9987982178A2E2E139C7BCBE04CA8A0E99E318D9AB76'
        'F988C8549F75ADD790BA4F81C176DA653C1A043F11A958E169B6D2319F4EEC1A',
      );

      final output = salsa20(Uint8List(131072), key, nonce: nonce);
      final blockXor = Uint8List(64);
      for (int i = 0; i < output.length; i += 64) {
        for (int j = 0; j < 64; ++j) {
          blockXor[j] ^= output[i + j];
        }
      }

      expect(blockXor, equals(expectedXor));
    });
  });

  group('correctness', () {
    test('encryption <-> decryption (convert)', () {
      var key = randomNumbers(32);
      var nonce = randomBytes(16);
      for (int j = 0; j < 100; ++j) {
        var text = randomNumbers(j);
        var bytes = Uint8List.fromList(text);
        var cipher = salsa20(text, key, nonce: nonce);
        var plain = salsa20(cipher, key, nonce: nonce);
        expect(bytes, equals(plain), reason: '[text: $j]');
      }
    });
    test('encryption <-> decryption (stream)', () async {
      var key = randomNumbers(32);
      var nonce = randomBytes(16);
      for (int j = 0; j < 100; ++j) {
        var text = randomNumbers(j);
        var bytes = Uint8List.fromList(text);
        var stream = Stream.fromIterable(text);
        var cipherStream = Salsa20(key, nonce).stream(stream);
        var plainStream = Salsa20(key, nonce).stream(cipherStream);
        var plain = await plainStream.toList();
        expect(plain, equals(bytes), reason: '[text: $j]');
      }
    });
    test('8-byte nonce: encryption <-> decryption (convert)', () {
      var key = randomNumbers(32);
      var nonce = randomBytes(8);
      for (int j = 0; j < 100; ++j) {
        var text = randomNumbers(j);
        var plain = Uint8List.fromList(text);
        var cipher = salsa20(text, key, nonce: nonce);
        var backwards = salsa20(cipher, key, nonce: nonce);
        expect(plain, equals(backwards), reason: '[text: $j]');
      }
    });

    group('counter increment', () {
      test('at 32-bit with 8-byte nonce', () {
        var key = randomBytes(32);
        var iv = fromHex('3122331221327845');
        var counter1 = Nonce64.int32(0xFFFFFFFF, 0x0F0F0FFF);
        var counter2 = Nonce64.int32(1, 0x0F0F1000);
        var message = Uint8List(256);
        var out1 = salsa20(message, key, nonce: iv, counter: counter1);
        var out2 = salsa20(message, key, nonce: iv, counter: counter2);
        expect(out1.skip(128), equals(out2.take(128)));
      });

      test('at 64-bit with 8-byte nonce', () {
        var key = randomBytes(32);
        var iv = fromHex('3122331221327845');
        var counter1 = Nonce64.int32(0xFFFFFFFF, 0xFFFFFFFF);
        var counter2 = Nonce64.int32(1);
        var message = Uint8List(256);
        var out1 = salsa20(message, key, nonce: iv, counter: counter1);
        var out2 = salsa20(message, key, nonce: iv, counter: counter2);
        expect(out1.skip(128), equals(out2.take(128)));
      });

      test('at 32-bit with 16-byte nonce', () {
        var key = randomBytes(32);
        var nonce1 = fromHex('3122331221327845FFFFFFFFFF0F0F0F');
        var nonce2 = fromHex('31223312213278450100000000100F0F');
        var message = Uint8List(256);
        var out1 = salsa20(message, key, nonce: nonce1);
        var out2 = salsa20(message, key, nonce: nonce2);
        expect(out1.skip(128), equals(out2.take(128)));
      });

      test('at 64-bit with 16-byte nonce', () {
        var key = randomBytes(32);
        var nonce1 = fromHex('3122331221327845FFFFFFFFFFFFFFFF');
        var nonce2 = fromHex('31223312213278450100000000000000');
        var message = Uint8List(256);
        var out1 = salsa20(message, key, nonce: nonce1);
        var out2 = salsa20(message, key, nonce: nonce2);
        expect(out1.skip(128), equals(out2.take(128)));
      });
    });
  });
}
