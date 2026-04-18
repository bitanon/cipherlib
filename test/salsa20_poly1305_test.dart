// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  group('Functionality test', () {
    test('name', () {
      expect(Salsa20Poly1305(Uint8List(32)).name, "Salsa20/Poly1305");
    });
    test('accepts empty message', () {
      final key = randomNumbers(32);
      final res = salsa20poly1305([], key);
      expect(res.data, equals([]));
      expect(res.mac.bytes.length, equals(16));
      final out = salsa20poly1305([], key, nonce: res.iv, mac: res.mac.bytes);
      expect(out.data, equals([]));
      expect(out.mac.hex(), equals(res.mac.hex()));
    });
    test('The key should be either 16 or 32 bytes', () {
      for (int i = 0; i < 100; ++i) {
        void cb() => salsa20poly1305([1], Uint8List(i));
        if (i == 16 || i == 32) {
          expect(() => cb(), returnsNormally, reason: 'length: $i');
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('Counter is not expected with 32-byte nonce', () {
      final key = Uint8List(32);
      final iv = Uint8List(32);
      final c = Nonce64.zero();
      expect(() => Salsa20Poly1305(key, nonce: iv, counter: c),
          throwsArgumentError);
    });
    test('The nonce should be either 8 or 16 bytes', () {
      var key = Uint8List(32);
      for (int i = 0; i < 100; ++i) {
        void cb() => salsa20poly1305([1], key, nonce: Uint8List(i));
        if (i == 8 || i == 16) {
          expect(() => cb(), returnsNormally, reason: 'length: $i');
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('returns the original nonce', () {
      final key = Uint8List(32);
      final nonce = List.filled(16, 1);
      final algo = Salsa20Poly1305(key, nonce: nonce);
      expect(algo.cipher.iv, equals(nonce));
    });
    test('random nonce is used if nonce is null, ', () {
      var key = randomNumbers(32);
      var text = randomBytes(100);
      salsa20poly1305(text, key);
    });
    test('reset iv', () {
      var x = Salsa20Poly1305(Uint8List(32));
      var iv = [...x.iv];
      var key1 = [...x.cipher.key];
      var key2 = [...x.this.mac.keypair];
      var tag1 = x.sign(const [1, 2, 3, 4]).mac.bytes;
      x.resetIV();
      expect(iv, isNot(equals(x.iv)));
      expect(key1, equals(x.cipher.key));
      expect(key2, isNot(equals(x.this.mac.keypair)));
      var tag2 = x.sign(const [1, 2, 3, 4]).mac.bytes;
      expect(tag1, isNot(equals(tag2)));
    });
  });

  test('encryption <-> decryption (convert)', () {
    var key = randomNumbers(32);
    var nonce = randomBytes(16);
    for (int j = 0; j < 100; ++j) {
      var text = randomBytes(j);
      var res = Salsa20Poly1305(key, nonce: nonce).convert(text);
      var verified = Salsa20Poly1305(key, nonce: nonce).convert(res);
      expect(verified, equals(text), reason: '[text size: $j]');
    }
  });

  test('sign and verify', () {
    for (int i = 0; i < 100; ++i) {
      final key = randomBytes(32);
      final iv = randomBytes(16);
      final aad = randomBytes(key[0]);
      final message = randomBytes(i);
      final instance = Salsa20Poly1305(key, nonce: iv, aad: aad);
      final res = instance.sign(message);
      expect(instance.verify(res.data, res.mac.bytes), isTrue);
    }
  });

  test('reset iv', () {
    var x = Salsa20Poly1305(Uint8List(32));
    var iv = [...x.iv];
    var key1 = [...x.cipher.key];
    var key2 = [...x.this.mac.keypair];
    x.resetIV();
    expect(iv, isNot(equals(x.iv)));
    expect(key1, equals(x.cipher.key));
    expect(key2, isNot(equals(x.this.mac.keypair)));
  });

  test('decrypt with invalid mac', () {
    var key = Uint8List(32);
    var nonce = Uint8List(16);
    var sample = Uint8List(150);
    var aad = Uint8List(16);
    var res = salsa20poly1305(
      sample,
      key,
      nonce: nonce,
      aad: aad,
    );
    expect(
      () => salsa20poly1305(
        res.data,
        key,
        mac: Uint8List(16),
        nonce: nonce,
        aad: aad,
      ),
      throwsA((e) => e is AssertionError),
    );
  });
}
