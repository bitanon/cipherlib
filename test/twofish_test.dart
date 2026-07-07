// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';
import 'package:test/test.dart';

import 'fixtures/twofish_vectors.dart';

void main() {
  group('validation', () {
    final key = Uint8List(32);
    final iv = Uint8List(16);
    final input = Uint8List(64);

    test("name is correct", () {
      expect(Twofish.noPadding(key).ecb().name, "Twofish/ECB/NoPadding");
      expect(Twofish.ansi(key).ecb().name, "Twofish/ECB/ANSI");
      expect(Twofish.byte(key).ecb().name, "Twofish/ECB/Byte");
      expect(Twofish.pkcs7(key).ecb().name, "Twofish/ECB/PKCS7");
      expect(Twofish(key).cbc(iv).name, "Twofish/CBC/PKCS7");
      expect(Twofish(key).ctr(iv).name, "Twofish/CTR/NoPadding");
    });

    test("encryptor and decryptor names are correct", () {
      expect(Twofish(key).ecb().encryptor.name, "Twofish#encrypt/ECB/PKCS7");
      expect(Twofish(key).ecb().decryptor.name, "Twofish#decrypt/ECB/PKCS7");
      expect(Twofish(key).cbc(iv).encryptor.name, "Twofish#encrypt/CBC/PKCS7");
      expect(Twofish(key).cbc(iv).decryptor.name, "Twofish#decrypt/CBC/PKCS7");
      expect(
          Twofish(key).ctr(iv).encryptor.name, "Twofish#cipher/CTR/NoPadding");
    });

    test("padding is correct", () {
      expect(Twofish.noPadding(key).ecb().padding, Padding.none);
      expect(Twofish.ansi(key).ecb().padding, Padding.ansi);
      expect(Twofish.byte(key).ecb().padding, Padding.byte);
      expect(Twofish.pkcs7(key).ecb().padding, Padding.pkcs7);
    });

    test('key must be 16, 24, or 32 bytes', () {
      for (int i = 0; i < 100; ++i) {
        final k = Uint8List(i);
        if (i == 16 || i == 24 || i == 32) {
          expect(() => Twofish(k).ecb().encrypt(input), returnsNormally,
              reason: 'length: $i');
          expect(() => Twofish(k).cbc(iv).encrypt(input), returnsNormally,
              reason: 'length: $i');
          expect(() => Twofish(k).ctr(iv).encrypt(input), returnsNormally,
              reason: 'length: $i');
        } else {
          expect(() => Twofish(k).ecb(), throwsStateError,
              reason: 'length: $i');
          expect(() => Twofish(k).cbc(iv), throwsStateError,
              reason: 'length: $i');
          expect(() => Twofish(k).ctr(iv), throwsStateError,
              reason: 'length: $i');
        }
      }
    });

    test('IV must be exactly 16 bytes', () {
      for (int i = 0; i < 20; ++i) {
        final iv = Uint8List(i);
        if (i == 16) {
          expect(() => Twofish(key).cbc(iv), returnsNormally,
              reason: 'length: $i');
          expect(() => Twofish(key).ctr(iv), returnsNormally,
              reason: 'length: $i');
        } else {
          expect(() => Twofish(key).cbc(iv), throwsStateError,
              reason: 'length: $i');
          expect(() => Twofish(key).ctr(iv), throwsStateError,
              reason: 'length: $i');
        }
      }
    });

    test('random IV is used if not provided', () {
      final a = TwofishInCBCMode(key);
      final b = TwofishInCTRMode(key);
      final c = TwofishInCTRMode.iv(key);
      expect(a.iv.length, 16);
      expect(b.iv.length, 16);
      expect(c.iv.length, 16);
      expect(() => a.decrypt(a.encrypt(input)), returnsNormally);
      expect(() => b.decrypt(b.encrypt(input)), returnsNormally);
      expect(() => c.decrypt(c.encrypt(input)), returnsNormally);
    });

    test('counter bits must be between 1 and 128', () {
      expect(() => Twofish(key).ctr(iv, 0), throwsStateError);
      expect(() => Twofish(key).ctr(iv, 1), returnsNormally);
      expect(() => Twofish(key).ctr(iv, 128), returnsNormally);
      expect(() => Twofish(key).ctr(iv, 129), throwsStateError);
    });

    test('throws error on invalid input size', () {
      final tf = Twofish.noPadding(key);
      expect(() => tf.ecb().encrypt(Uint8List(15)), throwsStateError);
      expect(() => tf.ecb().decrypt(Uint8List(15)), throwsStateError);
      expect(() => tf.cbc(iv).encrypt(Uint8List(17)), throwsStateError);
      expect(() => tf.cbc(iv).decrypt(Uint8List(17)), throwsStateError);
    });

    test('accepts empty message', () {
      expect(Twofish.noPadding(key).ecb().encrypt([]), isEmpty);
      expect(Twofish.noPadding(key).cbc(iv).encrypt([]), isEmpty);
      expect(Twofish(key).ctr(iv).encrypt([]), isEmpty);
    });

    test('reset iv', () {
      final cbc = Twofish(key).cbc(Uint8List.fromList(randomBytes(16)));
      final ctr = Twofish(key).ctr(Uint8List.fromList(randomBytes(16)));
      for (int j = 0; j < 20; ++j) {
        cbc.resetIV();
        ctr.resetIV();
        final inp = randomBytes(j);
        expect(toHex(cbc.decrypt(cbc.encrypt(inp))), equals(toHex(inp)),
            reason: '[cbc, size: $j]');
        expect(toHex(ctr.decrypt(ctr.encrypt(inp))), equals(toHex(inp)),
            reason: '[ctr, size: $j]');
      }
    });
  });

  // https://www.schneier.com/code/ecb_ival.txt
  group('Twofish ECB known-answer tables', () {
    test('128-bit keys', () {
      for (final item in twofish_ecb_128_vectors) {
        final tf = Twofish.noPadding(fromHex(item["key"]!)).ecb();
        final plain = fromHex(item["plain"]!);
        final cipher = fromHex(item["cipher"]!);
        expect(toHex(tf.encrypt(plain), upper: true), equals(item["cipher"]),
            reason: '[key: ${item["key"]}]');
        expect(toHex(tf.decrypt(cipher), upper: true), equals(item["plain"]),
            reason: '[key: ${item["key"]}]');
      }
    });
    test('192-bit keys', () {
      for (final item in twofish_ecb_192_vectors) {
        final tf = Twofish.noPadding(fromHex(item["key"]!)).ecb();
        final plain = fromHex(item["plain"]!);
        final cipher = fromHex(item["cipher"]!);
        expect(toHex(tf.encrypt(plain), upper: true), equals(item["cipher"]),
            reason: '[key: ${item["key"]}]');
        expect(toHex(tf.decrypt(cipher), upper: true), equals(item["plain"]),
            reason: '[key: ${item["key"]}]');
      }
    });
    test('256-bit keys', () {
      for (final item in twofish_ecb_256_vectors) {
        final tf = Twofish.noPadding(fromHex(item["key"]!)).ecb();
        final plain = fromHex(item["plain"]!);
        final cipher = fromHex(item["cipher"]!);
        expect(toHex(tf.encrypt(plain), upper: true), equals(item["cipher"]),
            reason: '[key: ${item["key"]}]');
        expect(toHex(tf.decrypt(cipher), upper: true), equals(item["plain"]),
            reason: '[key: ${item["key"]}]');
      }
    });
  });

  group('correctness', () {
    test('encrypt <-> decrypt (ECB)', () {
      for (int j = 0; j < 100; ++j) {
        final key = randomBytes([16, 24, 32][j % 3]);
        final tf = Twofish(key).ecb();
        final inp = randomBytes(j);
        expect(toHex(tf.decrypt(tf.encrypt(inp))), equals(toHex(inp)),
            reason: '[size: $j]');
      }
    });
    test('encrypt <-> decrypt (CBC)', () {
      for (int j = 0; j < 100; ++j) {
        final key = randomBytes([16, 24, 32][j % 3]);
        final tf = Twofish(key).cbc(randomBytes(16));
        final inp = randomBytes(j);
        expect(toHex(tf.decrypt(tf.encrypt(inp))), equals(toHex(inp)),
            reason: '[size: $j]');
      }
    });
    test('encrypt <-> decrypt (CTR)', () {
      for (int j = 0; j < 100; ++j) {
        final key = randomBytes([16, 24, 32][j % 3]);
        final tf = Twofish(key).ctr(randomBytes(16));
        final inp = randomBytes(j);
        expect(toHex(tf.decrypt(tf.encrypt(inp))), equals(toHex(inp)),
            reason: '[size: $j]');
      }
    });
  });

  group('counter increment', () {
    // CTR keystream blocks must match the ECB encryption of counter blocks
    test('carry crosses the 32, 64, and 96-bit boundaries', () {
      final key = randomBytes(16);
      final iv = fromHex('00000000FFFFFFFFFFFFFFFFFFFFFFFF');
      final ecb = Twofish.noPadding(key).ecb();
      final k0 = ecb.encrypt(fromHex('00000000FFFFFFFFFFFFFFFFFFFFFFFF'));
      final k1 = ecb.encrypt(fromHex('00000001000000000000000000000000'));
      final out = Twofish(key).ctr(iv, 128).encrypt(Uint8List(32));
      expect(toHex(out), equals(toHex([...k0, ...k1])));
    });
    test('carry is discarded beyond 72 counter bits', () {
      final key = randomBytes(16);
      final iv = fromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF');
      final ecb = Twofish.noPadding(key).ecb();
      final k0 = ecb.encrypt(fromHex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'));
      final k1 = ecb.encrypt(fromHex('FFFFFFFFFFFFFF000000000000000000'));
      final out = Twofish(key).ctr(iv, 72).encrypt(Uint8List(32));
      expect(toHex(out), equals(toHex([...k0, ...k1])));
    });
  });

  group('stream support', () {
    Stream<List<int>> chunked(List<int> data) async* {
      for (int i = 0; i < data.length; i += 7) {
        yield data.sublist(i, i + 7 > data.length ? data.length : i + 7);
      }
    }

    test('bind output matches convert output (ECB)', () async {
      final key = randomBytes(16);
      final inp = randomBytes(100);
      final tf = Twofish(key).ecb();
      final enc =
          await tf.encryptor.bind(chunked(inp)).expand((x) => x).toList();
      expect(enc, equals(tf.encrypt(inp)));
      final dec =
          await tf.decryptor.bind(chunked(enc)).expand((x) => x).toList();
      expect(dec, equals(inp));
    });

    test('bind output matches convert output (CBC)', () async {
      final key = randomBytes(24);
      final inp = randomBytes(100);
      final tf = Twofish(key).cbc(randomBytes(16));
      final enc =
          await tf.encryptor.bind(chunked(inp)).expand((x) => x).toList();
      expect(enc, equals(tf.encrypt(inp)));
      final dec =
          await tf.decryptor.bind(chunked(enc)).expand((x) => x).toList();
      expect(dec, equals(inp));
    });

    test('bind output matches convert output (CTR)', () async {
      final key = randomBytes(32);
      final inp = randomBytes(100);
      final tf = Twofish(key).ctr(randomBytes(16));
      final enc =
          await tf.encryptor.bind(chunked(inp)).expand((x) => x).toList();
      expect(enc, equals(tf.encrypt(inp)));
      final dec =
          await tf.decryptor.bind(chunked(enc)).expand((x) => x).toList();
      expect(dec, equals(inp));
    });

    test('bind emits independent full chunks', () async {
      final key = randomBytes(16);
      final inp = randomBytes(64);
      final tf = Twofish.noPadding(key).ecb();
      final chunks = await tf.encryptor.bind(chunked(inp)).toList();
      final again = tf.encrypt(inp);
      expect(chunks.expand((x) => x).toList(), equals(again));
      // mutating one chunk must not affect another
      chunks[0][0] ^= 0xFF;
      expect(chunks.expand((x) => x).toList(), isNot(equals(again)));
    });

    test('bind throws on invalid input size without padding', () {
      final tf = Twofish.noPadding(randomBytes(16));
      final iv = randomBytes(16);
      final inp = randomBytes(17);
      expect(tf.ecb().encryptor.bind(chunked(inp)).drain<void>(),
          throwsStateError);
      expect(tf.ecb().decryptor.bind(chunked(inp)).drain<void>(),
          throwsStateError);
      expect(tf.cbc(iv).encryptor.bind(chunked(inp)).drain<void>(),
          throwsStateError);
      expect(tf.cbc(iv).decryptor.bind(chunked(inp)).drain<void>(),
          throwsStateError);
    });

    test('cast is unsupported for StreamCipher', () {
      final tf = Twofish(Uint8List(16));
      expect(() => tf.ecb().encryptor.cast(), throwsUnsupportedError);
      expect(
          () => tf.cbc(Uint8List(16)).encryptor.cast(), throwsUnsupportedError);
      expect(
          () => tf.ctr(Uint8List(16)).encryptor.cast(), throwsUnsupportedError);
    });
  });
}
