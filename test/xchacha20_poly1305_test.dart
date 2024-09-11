// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/src/cipherlib_base.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

import 'fixures/xchacha20_vectors.dart';
import 'utils.dart';

void main() {
  group('Functionality test', () {
    test('name', () {
      expect(XChaCha20Poly1305(Uint8List(32)).name, "XChaCha20/Poly1305");
    });
    test('accepts empty message', () {
      final key = randomNumbers(32);
      final res = xchacha20poly1305([], key);
      expect(res.data, equals([]));
      expect(res.tag.bytes.length, equals(16));
      final out = xchacha20poly1305([], key, nonce: res.iv, mac: res.tag.bytes);
      expect(out.data, equals([]));
      expect(out.tag.hex(), equals(res.tag.hex()));
    });
    test('The key should be either 16 or 32 bytes', () {
      for (int i = 0; i < 100; ++i) {
        void cb() => xchacha20poly1305([1], Uint8List(i));
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
        void cb() => xchacha20poly1305([1], key, nonce: Uint8List(i));
        if (i == 24 || i == 28 || i == 32) {
          cb();
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('Counter is not expected with 32-byte nonce', () {
      final key = Uint8List(32);
      final c = Nonce64.zero();
      expect(() => XChaCha20Poly1305(key, nonce: Uint8List(32), counter: c),
          throwsArgumentError);
    });
    test('returns the original nonce', () {
      final key = Uint8List(32);
      final nonce = List.filled(32, 1);
      final algo = XChaCha20Poly1305(key, nonce: nonce);
      expect(algo.cipher.iv, equals(nonce));
    });
    test('random nonce is used if nonce is null, ', () {
      var key = randomNumbers(32);
      var text = randomBytes(100);
      xchacha20(text, key);
    });
    test('reset iv', () {
      var x = XChaCha20Poly1305(Uint8List(32));
      var iv = [...x.iv];
      var key1 = [...x.cipher.key];
      var key2 = [...x.mac.keypair];
      var activeIV = [...x.cipher.activeIV];
      x.resetIV();
      expect(iv, isNot(equals(x.iv)));
      expect(key1, isNot(equals(x.cipher.key)));
      expect(key2, isNot(equals(x.mac.keypair)));
      expect(activeIV, isNot(equals(x.cipher.activeIV)));
    });
  });

  test('sign and verify', () {
    for (int i = 1; i < 100; ++i) {
      final key = randomBytes(32);
      final iv = randomBytes(24);
      final aad = randomBytes(key[0]);
      final message = randomBytes(i);
      final res = xchacha20poly1305(
        message,
        key,
        nonce: iv,
        aad: aad,
      );
      final verify = xchacha20poly1305(
        res.data,
        key,
        nonce: iv,
        aad: aad,
        mac: res.tag.bytes,
      );
      expect(verify.data, equals(message));
      expect(res.tag.hex(), isNot(equals(verify.tag.hex())));
      expect(
          () => xchacha20poly1305(
                res.data,
                key,
                nonce: iv,
                aad: aad,
                mac: verify.tag.bytes,
              ),
          throwsA(isA<AssertionError>()));
    }
  });

  // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
  group('Example A.3.1 - draft-irtf-cfrg-xchacha-03 (A.3.1)', () {
    final key = fromHex(
      '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
    );
    final iv = fromHex(
      '404142434445464748494a4b4c4d4e4f5051525354555657',
    );
    final aad = fromHex(
      '50515253c0c1c2c3c4c5c6c7',
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
    final tag = fromHex(
      'c0875924c1c7987947deafd8780acf49',
    );

    test('sign', () {
      final output = xchacha20poly1305(
        plain,
        key,
        nonce: iv,
        aad: aad,
      );
      expect(output.data, equals(cipher));
      expect(output.tag.bytes, equals(tag));
    });
    test('decrypt', () {
      final output = xchacha20poly1305(
        cipher,
        key,
        nonce: iv,
        aad: aad,
        mac: tag,
      );
      expect(output.data, equals(plain));
    });
  });

  // https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305_vectors_test.go
  test('golang-crypto test vectors for XChaCha20-Poly1305', () {
    for (final item in xchacha20_vectors) {
      final inp = fromHex(item['plain']!);
      final aad = fromHex(item['aad']!);
      final key = fromHex(item['key']!);
      final iv = fromHex(item['nonce']!);
      final out = fromHex(item['out']!).take(inp.length).toList();
      final tag = fromHex(item['out']!).skip(inp.length).toList();
      final res = xchacha20poly1305(inp, key, nonce: iv, aad: aad);
      expect(toHex(res.data), equals(toHex(out)));
      expect(res.tag.hex(), equals(toHex(tag)));
    }
  });
}
