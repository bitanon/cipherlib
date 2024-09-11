// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

import 'fixures/xchacha20_vectors.dart';
import 'utils.dart';

void main() {
  group('Functionality test', () {
    test('name', () {
      expect(XChaCha20(Uint8List(32)).name, "XChaCha20");
    });
    test('accepts empty message', () {
      final key = randomNumbers(32);
      expect(xchacha20([], key), equals([]));
    });
    test('The key should be either 16 or 32 bytes', () {
      for (int i = 0; i < 100; ++i) {
        void cb() => xchacha20([1], Uint8List(i));
        if (i == 16 || i == 32) {
          cb();
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('The nonce should be 24, 28, 32 bytes', () {
      var key = Uint8List(32);
      for (int i = 0; i < 100; ++i) {
        void cb() => xchacha20([1], key, nonce: Uint8List(i));
        if (i == 24 || i == 28 || i == 32) {
          cb();
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('If counter is not provided, default one is used (24 byte nonce)', () {
      final key = Uint8List(32);
      final nonce = List.filled(24, 1);
      final algo = XChaCha20(key, nonce);
      expect(algo.activeIV,
          equals([1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]));
    });
    test('Counter is set correctly when provided  (24 byte nonce)', () {
      final key = Uint8List(32);
      final nonce = List.filled(24, 1);
      final counter = Nonce64.bytes([2, 2, 2, 2, 2, 2, 2, 2]);
      final algo = XChaCha20(key, nonce, counter);
      expect(algo.activeIV,
          equals([2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1]));
    });
    test('If counter is not provided, default one is used (28 byte nonce)', () {
      final key = Uint8List(32);
      final nonce = List.filled(28, 1);
      final algo = XChaCha20(key, nonce);
      expect(algo.activeIV,
          equals([1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]));
    });
    test('Counter is set correctly when provided  (28 byte nonce)', () {
      final key = Uint8List(32);
      final nonce = List.filled(28, 1);
      final counter = Nonce64.bytes([2, 2, 2, 2, 2, 2, 2, 2]);
      final algo = XChaCha20(key, nonce, counter);
      expect(algo.activeIV,
          equals([2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]));
    });
    test('Counter is not expected with 32-byte nonce', () {
      final key = Uint8List(32);
      final c = Nonce64.zero();
      expect(() => XChaCha20(key, Uint8List(32), c), throwsArgumentError);
    });
    test('random nonce is used if nonce is null, ', () {
      var key = randomNumbers(32);
      var text = randomBytes(100);
      xchacha20(text, key);
    });
    test('reset iv', () {
      var x = XChaCha20(Uint8List(32));
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
    test('XChaCha20: encryption <=> decryption', () {
      for (int i = 0; i < 100; ++i) {
        final key = randomBytes(32);
        final iv = randomBytes(24);
        final message = randomBytes(i);
        final cipher = xchacha20(message, key, nonce: iv);
        final plain = xchacha20(cipher, key, nonce: iv);
        expect(plain, equals(message));
      }
    });
    test('XChaCha20: encryption <-> decryption (stream)', () async {
      for (int j = 0; j < 100; ++j) {
        var key = randomNumbers(16);
        var nonce = randomBytes(24);
        var text = randomNumbers(j);
        var bytes = Uint8List.fromList(text);
        var stream = Stream.fromIterable(text);
        var cipherStream = xchacha20Stream(stream, key, nonce: nonce);
        var plainStream = xchacha20Stream(cipherStream, key, nonce: nonce);
        var plain = await plainStream.toList();
        expect(bytes, equals(plain), reason: '[text: $j]');
      }
    });
  });

  test('HChaCha20 subkey', () {
    final key = fromHex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    );
    final iv = fromHex(
      '000000090000004a00000000314159270000000000000000',
    );
    final subkey = fromHex(
      '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc',
    );
    expect(XChaCha20(key, iv).key, equals(subkey));
  });

  // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
  group('Example A.3.1 - draft-irtf-cfrg-xchacha-03 (A.3.1)', () {
    final key = fromHex(
      '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
    );
    final iv = fromHex(
      '404142434445464748494a4b4c4d4e4f5051525354555657',
    );
    final plain = fromHex(
      '4c616469657320616e642047656e746c656d656e206f662074686520636c6173'
      '73206f66202739393a204966204920636f756c64206f6666657220796f75206f'
      '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73'
      '637265656e20776f756c642062652069742e',
    );
    final cipher = fromHex(
      'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb'
      '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452'
      '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9'
      '21f9664c97637da9768812f615c68b13b52e',
    );

    test('encrypt', () {
      final output = xchacha20(plain, key, nonce: iv);
      expect(output, equals(cipher));
    });
    test('decrypt', () {
      final output = xchacha20(cipher, key, nonce: iv);
      expect(output, equals(plain));
    });
  });

  group('Example A.3.2.1 - draft-irtf-cfrg-xchacha-03', () {
    final counter = Nonce64.int32(0);
    final key = fromHex(
      '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
    );
    final iv = fromHex(
      '404142434445464748494a4b4c4d4e4f5051525354555658',
    );
    final plain = fromHex(
      '5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973'
      '20616c736f206b6e6f776e2061732074686520417369617469632077696c6420'
      '646f672c2072656420646f672c20616e642077686973746c696e6720646f672e'
      '2049742069732061626f7574207468652073697a65206f662061204765726d61'
      '6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061'
      '206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c'
      '757369766520616e6420736b696c6c6564206a756d70657220697320636c6173'
      '736966696564207769746820776f6c7665732c20636f796f7465732c206a6163'
      '6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963'
      '2066616d696c792043616e696461652e',
    );
    final cipher = fromHex(
      '4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9'
      '8d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d'
      '4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0da'
      'ece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e744'
      '3056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b74814240'
      '7c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c'
      '09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae'
      '577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486c'
      'cb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a663'
      '93b93111c1a55dd7421a10184974c7c5',
    );

    test('encrypt', () {
      final output = xchacha20(plain, key, nonce: iv, counter: counter);
      expect(output, equals(cipher));
    });
    test('decrypt', () {
      final output = xchacha20(cipher, key, nonce: iv, counter: counter);
      expect(output, equals(plain));
    });
  });

  group('Example A.3.2.2 - draft-irtf-cfrg-xchacha-03', () {
    final counter = Nonce64.int32(1);
    final key = fromHex(
      '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
    );
    final iv = fromHex(
      '404142434445464748494a4b4c4d4e4f5051525354555658',
    );
    final plain = fromHex(
      '5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973'
      '20616c736f206b6e6f776e2061732074686520417369617469632077696c6420'
      '646f672c2072656420646f672c20616e642077686973746c696e6720646f672e'
      '2049742069732061626f7574207468652073697a65206f662061204765726d61'
      '6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061'
      '206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c'
      '757369766520616e6420736b696c6c6564206a756d70657220697320636c6173'
      '736966696564207769746820776f6c7665732c20636f796f7465732c206a6163'
      '6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963'
      '2066616d696c792043616e696461652e',
    );
    final cipher = fromHex(
      '7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87'
      'ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05'
      '3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f'
      '7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201'
      '12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc'
      '047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63'
      'd595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73'
      'c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4'
      'd0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683'
      '8a9c71f70b5b5907a66f7ea49aadc409',
    );

    test('encrypt', () {
      final output = xchacha20(plain, key, nonce: iv, counter: counter);
      expect(output, equals(cipher));
    });
    test('decrypt', () {
      final output = xchacha20(cipher, key, nonce: iv, counter: counter);
      expect(output, equals(plain));
    });
  });

  // https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305_vectors_test.go
  test('golang-crypto test vectors for XChaCha20', () {
    for (final item in xchacha20_vectors) {
      final inp = fromHex(item['plain']!);
      final key = fromHex(item['key']!);
      final iv = fromHex(item['nonce']!);
      final out = fromHex(item['out']!).take(inp.length).toList();
      final res = xchacha20(inp, key, nonce: iv);
      expect(toHex(res), equals(toHex(out)));
    }
  });
}
