// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/src/cipherlib_base.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  group('Functionality test', () {
    test('name', () {
      expect(XSalsa20Poly1305(Uint8List(32)).name, "XSalsa20/Poly1305");
    });
    test('accepts empty message', () {
      final key = randomNumbers(32);
      final res = xsalsa20poly1305([], key);
      expect(res.data, equals([]));
      expect(res.tag.bytes.length, equals(16));
      final out = xsalsa20poly1305([], key, nonce: res.iv, mac: res.tag.bytes);
      expect(out.data, equals([]));
      expect(out.tag.hex(), equals(res.tag.hex()));
    });
    test('The key should be either 16 or 32 bytes', () {
      for (int i = 0; i < 100; ++i) {
        void cb() => xsalsa20poly1305([1], Uint8List(i));
        if (i == 16 || i == 32) {
          cb();
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('Counter is not expected with 32-byte nonce', () {
      final key = Uint8List(32);
      final iv = Uint8List(32);
      final c = Nonce64.zero();
      expect(() => XSalsa20Poly1305(key, nonce: iv, counter: c),
          throwsArgumentError);
    });
    test('The nonce should be either 24 or 32 bytes', () {
      var key = Uint8List(32);
      for (int i = 0; i < 100; ++i) {
        void cb() => xsalsa20poly1305([1], key, nonce: Uint8List(i));
        if (i == 24 || i == 32) {
          cb();
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('returns the original nonce', () {
      final key = Uint8List(32);
      final nonce = List.filled(32, 1);
      final algo = XSalsa20Poly1305(key, nonce: nonce);
      expect(algo.cipher.iv, equals(nonce));
    });
    test('random nonce is used if nonce is null, ', () {
      var key = randomNumbers(32);
      var text = randomBytes(100);
      xsalsa20poly1305(text, key);
    });
    test('reset iv', () {
      var x = XSalsa20Poly1305(Uint8List(32));
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
      final res = xsalsa20poly1305(
        message,
        key,
        nonce: iv,
        aad: aad,
      );
      final verify = xsalsa20poly1305(
        res.data,
        key,
        nonce: iv,
        aad: aad,
        mac: res.tag.bytes,
      );
      expect(verify.data, equals(message));
      expect(res.tag.hex(), isNot(equals(verify.tag.hex())));
      expect(
          () => xsalsa20poly1305(
                res.data,
                key,
                nonce: iv,
                aad: aad,
                mac: verify.tag.bytes,
              ),
          throwsA(isA<AssertionError>()));
    }
  });
}
