// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/src/cipherlib_base.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  group('Functionality test', () {
    test('name', () {
      expect(XSalsa20(Uint8List(32)).name, "XSalsa20");
    });
    test('accepts empty message', () {
      final key = randomNumbers(32);
      expect(xsalsa20([], key), equals([]));
    });
    test('The key should be either 16 or 32 bytes', () {
      for (int i = 0; i < 100; ++i) {
        void cb() => xsalsa20([1], Uint8List(i));
        if (i == 16 || i == 32) {
          cb();
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('Counter is not expected with 32-byte nonce', () {
      final key = Uint8List(32);
      final c = Nonce64.zero();
      expect(() => XSalsa20(key, Uint8List(32), c), throwsArgumentError);
    });
    test('The nonce should be either 24 or 32 bytes', () {
      var key = Uint8List(32);
      for (int i = 0; i < 100; ++i) {
        void cb() => xsalsa20([1], key, nonce: Uint8List(i));
        if (i == 24 || i == 32) {
          cb();
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('If counter is not provided, default one is used', () {
      final key = Uint8List(32);
      final nonce = List.filled(24, 1);
      final algo = XSalsa20(key, nonce);
      expect(algo.activeIV,
          equals([1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]));
    });
    test('Counter is set correctly when provided', () {
      final key = Uint8List(32);
      final nonce = List.filled(24, 1);
      final counter = Nonce64.bytes([2, 2, 2, 2, 2, 2, 2, 2]);
      final algo = XSalsa20(key, nonce, counter);
      expect(algo.activeIV,
          equals([1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2]));
    });
    test('random nonce is used if nonce is null, ', () {
      var key = randomNumbers(32);
      var text = randomBytes(100);
      xsalsa20(text, key);
    });
    test('reset iv', () {
      var x = XSalsa20(Uint8List(32));
      var iv = [...x.iv];
      var key = [...x.key];
      var activeIV = [...x.activeIV];
      x.resetIV();
      expect(iv, isNot(equals(x.iv)));
      expect(key, isNot(equals(x.key)));
      expect(activeIV, isNot(equals(x.activeIV)));
    });
  });

  group('correctness', () {
    test('encryption <=> decryption', () {
      for (int i = 0; i < 20; ++i) {
        final key = randomBytes(32);
        final iv = randomBytes(24);
        final message = randomBytes(96);
        final cipher = xsalsa20(message, key, nonce: iv);
        final plain = xsalsa20(cipher, key, nonce: iv);
        expect(plain, equals(message));
      }
    });
    test('encryption <-> decryption (stream)', () async {
      for (int j = 0; j < 100; ++j) {
        var key = randomNumbers(16);
        var nonce = randomBytes(24);
        var text = randomNumbers(j);
        var bytes = Uint8List.fromList(text);
        var stream = Stream.fromIterable(text);
        var cipherStream = xsalsa20Stream(stream, key, nonce: nonce);
        var plainStream = xsalsa20Stream(cipherStream, key, nonce: nonce);
        var plain = await plainStream.toList();
        expect(bytes, equals(plain), reason: '[text: $j]');
      }
    });
  });

  // https://github.com/golang/crypto/blob/master/salsa20/salsa20_test.go
  group('Test 1', () {
    final key = 'this is 32-byte key for xsalsa20'.codeUnits;
    final iv = '24-byte nonce for xsalsa'.codeUnits;
    final plain = "Hello world!";
    final cipher = [
      0x00, 0x2d, 0x45, 0x13, 0x84, 0x3f, 0xc2, 0x40, 0xc4, 0x01, 0xe5, 0x41 //
    ];

    test('encrypt', () {
      final output = xsalsa20(plain.codeUnits, key, nonce: iv);
      expect(toHex(output), equals(toHex(cipher)));
    });
    test('decrypt', () {
      final output = xsalsa20(cipher, key, nonce: iv);
      expect(String.fromCharCodes(output), equals(plain));
    });
  });

  group('Test 2', () {
    final key = 'this is 32-byte key for xsalsa20'.codeUnits;
    final iv = '24-byte nonce for xsalsa'.codeUnits;
    final plain = Uint8List(64);
    final cipher = [
      0x48, 0x48, 0x29, 0x7f, 0xeb, 0x1f, 0xb5, 0x2f, 0xb6, //
      0x6d, 0x81, 0x60, 0x9b, 0xd5, 0x47, 0xfa, 0xbc, 0xbe, 0x70,
      0x26, 0xed, 0xc8, 0xb5, 0xe5, 0xe4, 0x49, 0xd0, 0x88, 0xbf,
      0xa6, 0x9c, 0x08, 0x8f, 0x5d, 0x8d, 0xa1, 0xd7, 0x91, 0x26,
      0x7c, 0x2c, 0x19, 0x5a, 0x7f, 0x8c, 0xae, 0x9c, 0x4b, 0x40,
      0x50, 0xd0, 0x8c, 0xe6, 0xd3, 0xa1, 0x51, 0xec, 0x26, 0x5f,
      0x3a, 0x58, 0xe4, 0x76, 0x48,
    ];

    test('encrypt', () {
      final output = xsalsa20(plain, key, nonce: iv);
      expect(toHex(output), equals(toHex(cipher)));
    });
    test('decrypt', () {
      final output = xsalsa20(cipher, key, nonce: iv);
      expect(toHex(output), equals(toHex(plain)));
    });
  });

  group('Test 3', () {
    final key = fromHex(
      '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
    );
    final iv = '@ABCDEFGHIJKLMNOPQRSTUVW'.codeUnits;
    final plain = "Ladies and Gentlemen of the class of '99: If I could offer "
        "you only one tip for the future, sunscreen would be it.";
    final cipher =
        'f19dd4a85bbc672fac7ba3fed500022ef550d633721cea0ee4a241ebe57c3a549'
        '1855bab6a8df5a62cd6d942874931652431fb0512fdc1f83dfbc66e83b5a4f642'
        '7a817ce982d4f269d043468dbf30222d7a17ccdd05d65568e90f81c1b06ee9ff8'
        '3df1f1acaaa5e9bba43e4c99ac3094e2e';

    test('encrypt', () {
      final output = xsalsa20(plain.codeUnits, key, nonce: iv);
      expect(toHex(output), equals(cipher));
    });
    test('decrypt', () {
      final output = xsalsa20(fromHex(cipher), key, nonce: iv);
      expect(String.fromCharCodes(output), equals(plain));
    });
  });

  group('Test 4', () {
    final key = fromHex(
      '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
    );
    final iv = '@ABCDEFGHIJKLMNOPQRSTUVW'.codeUnits;
    final plain = Uint8List(128);
    final cipher =
        'bdfcb0c13ecf474ec21f83b9b06e7642903db35d52738c2e90ca24cb86105b27'
        'e2a534cd4aaacc9f16f69024a70011064b4497613292a79e5889e617ecc08499'
        '2c16f85c86ecb1d21db93366ebd04202591272ecbb70a2201a8c23a1b2c5009a'
        '9cf1ba7a74eadd31eed627c4abffe3603a00a019c3db0622439287d951e3c685';

    test('encrypt', () {
      final output = xsalsa20(plain, key, nonce: iv);
      expect(toHex(output), equals(cipher));
    });
    test('decrypt', () {
      final output = xsalsa20(fromHex(cipher), key, nonce: iv);
      expect(output, equals(plain));
    });
  });
}
