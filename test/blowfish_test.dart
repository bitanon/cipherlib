// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';
import 'package:test/test.dart';

import 'fixtures/blowfish_vectors.dart';

void main() {
  group('validation', () {
    final key = Uint8List(16);
    final iv = Uint8List(8);
    final input = Uint8List(64);

    test("name is correct", () {
      expect(Blowfish.noPadding(key).ecb().name, "Blowfish/ECB/NoPadding");
      expect(Blowfish.ansi(key).ecb().name, "Blowfish/ECB/ANSI");
      expect(Blowfish.byte(key).ecb().name, "Blowfish/ECB/Byte");
      expect(Blowfish.pkcs7(key).ecb().name, "Blowfish/ECB/PKCS7");
      expect(Blowfish(key).cbc(iv).name, "Blowfish/CBC/PKCS7");
      expect(Blowfish(key).ctr(iv).name, "Blowfish/CTR/NoPadding");
    });

    test("encryptor and decryptor names are correct", () {
      expect(Blowfish(key).ecb().encryptor.name, "Blowfish#encrypt/ECB/PKCS7");
      expect(Blowfish(key).ecb().decryptor.name, "Blowfish#decrypt/ECB/PKCS7");
      expect(
          Blowfish(key).cbc(iv).encryptor.name, "Blowfish#encrypt/CBC/PKCS7");
      expect(
          Blowfish(key).cbc(iv).decryptor.name, "Blowfish#decrypt/CBC/PKCS7");
      expect(Blowfish(key).ctr(iv).encryptor.name,
          "Blowfish#cipher/CTR/NoPadding");
    });

    test("padding is correct", () {
      expect(Blowfish.noPadding(key).ecb().padding, Padding.none);
      expect(Blowfish.ansi(key).ecb().padding, Padding.ansi);
      expect(Blowfish.byte(key).ecb().padding, Padding.byte);
      expect(Blowfish.pkcs7(key).ecb().padding, Padding.pkcs7);
    });

    test('key must be between 1 and 56 bytes', () {
      for (int i = 0; i < 100; ++i) {
        final k = Uint8List(i);
        if (i >= 1 && i <= 56) {
          expect(() => Blowfish(k).ecb().encrypt(input), returnsNormally,
              reason: 'length: $i');
          expect(() => Blowfish(k).cbc(iv).encrypt(input), returnsNormally,
              reason: 'length: $i');
          expect(() => Blowfish(k).ctr(iv).encrypt(input), returnsNormally,
              reason: 'length: $i');
        } else {
          expect(() => Blowfish(k).ecb(), throwsStateError,
              reason: 'length: $i');
          expect(() => Blowfish(k).cbc(iv), throwsStateError,
              reason: 'length: $i');
          expect(() => Blowfish(k).ctr(iv), throwsStateError,
              reason: 'length: $i');
        }
      }
    });

    test('IV must be exactly 8 bytes', () {
      for (int i = 0; i < 20; ++i) {
        final iv = Uint8List(i);
        if (i == 8) {
          expect(() => Blowfish(key).cbc(iv), returnsNormally,
              reason: 'length: $i');
          expect(() => Blowfish(key).ctr(iv), returnsNormally,
              reason: 'length: $i');
        } else {
          expect(() => Blowfish(key).cbc(iv), throwsStateError,
              reason: 'length: $i');
          expect(() => Blowfish(key).ctr(iv), throwsStateError,
              reason: 'length: $i');
        }
      }
    });

    test('random IV is used if not provided', () {
      final a = BlowfishInCBCMode(key);
      final b = BlowfishInCTRMode(key);
      expect(a.iv.length, 8);
      expect(b.iv.length, 8);
      expect(() => a.decrypt(a.encrypt(input)), returnsNormally);
      expect(() => b.decrypt(b.encrypt(input)), returnsNormally);
    });

    test('counter bits must be between 1 and 64', () {
      expect(() => Blowfish(key).ctr(iv, 0), throwsStateError);
      expect(() => Blowfish(key).ctr(iv, 1), returnsNormally);
      expect(() => Blowfish(key).ctr(iv, 64), returnsNormally);
      expect(() => Blowfish(key).ctr(iv, 65), throwsStateError);
    });

    test('throws error on invalid input size', () {
      final bf = Blowfish.noPadding(key);
      expect(() => bf.ecb().encrypt(Uint8List(7)), throwsStateError);
      expect(() => bf.ecb().decrypt(Uint8List(7)), throwsStateError);
      expect(() => bf.cbc(iv).encrypt(Uint8List(9)), throwsStateError);
      expect(() => bf.cbc(iv).decrypt(Uint8List(9)), throwsStateError);
    });

    test('accepts empty message', () {
      expect(Blowfish.noPadding(key).ecb().encrypt([]), isEmpty);
      expect(Blowfish.noPadding(key).cbc(iv).encrypt([]), isEmpty);
      expect(Blowfish(key).ctr(iv).encrypt([]), isEmpty);
    });

    test('reset iv', () {
      final cbc = Blowfish(key).cbc(Uint8List.fromList(randomBytes(8)));
      final ctr = Blowfish(key).ctr(Uint8List.fromList(randomBytes(8)));
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

  // Test vectors by Eric Young, from the Blowfish page by Bruce Schneier:
  // https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt
  group('Eric Young ECB test vectors', () {
    test('encrypt and decrypt', () {
      for (final item in blowfish_ecb_vectors) {
        final key = fromHex(item["key"]!);
        final plain = fromHex(item["plain"]!);
        final cipher = fromHex(item["cipher"]!);
        final bf = Blowfish.noPadding(key).ecb();
        expect(toHex(bf.encrypt(plain), upper: true), equals(item["cipher"]),
            reason: '[key: ${item["key"]}]');
        expect(toHex(bf.decrypt(cipher), upper: true), equals(item["plain"]),
            reason: '[key: ${item["key"]}]');
      }
    });
  });

  group('Eric Young set_key test vectors', () {
    test('variable key lengths of 1 to 24 bytes', () {
      final plain = fromHex(blowfish_setkey_plain);
      for (final item in blowfish_setkey_vectors) {
        final key = fromHex(item["key"]!);
        final bf = Blowfish.noPadding(key).ecb();
        expect(toHex(bf.encrypt(plain), upper: true), equals(item["cipher"]),
            reason: '[key: ${item["key"]}]');
      }
    });
  });

  group('Eric Young chaining mode test vectors', () {
    // data is zero-padded to the block boundary in the original test
    final key = fromHex('0123456789ABCDEFF0E1D2C3B4A59687');
    final iv = fromHex('FEDCBA9876543210');
    final data = fromHex(
      '37363534333231204E6F77206973207468652074696D6520666F722000',
    );
    final cbcOut =
        '6B77B4D63006DEE605B156E27403979358DEB9E7154616D959F1652BD5FF92CC';

    test('cbc encrypt', () {
      final cipher = Blowfish(key, Padding.zero).cbc(iv).encrypt(data);
      expect(toHex(cipher, upper: true), equals(cbcOut));
    });
    test('cbc decrypt', () {
      final plain = Blowfish.noPadding(key).cbc(iv).decrypt(fromHex(cbcOut));
      expect(toHex(plain), equals(toHex([...data, 0, 0, 0])));
    });
  });

  group('correctness', () {
    test('encrypt <-> decrypt (ECB)', () {
      for (int j = 0; j < 100; ++j) {
        final key = randomBytes((j % 56) + 1);
        final bf = Blowfish(key).ecb();
        final inp = randomBytes(j);
        expect(toHex(bf.decrypt(bf.encrypt(inp))), equals(toHex(inp)),
            reason: '[size: $j]');
      }
    });
    test('encrypt <-> decrypt (CBC)', () {
      for (int j = 0; j < 100; ++j) {
        final key = randomBytes((j % 56) + 1);
        final bf = Blowfish(key).cbc(randomBytes(8));
        final inp = randomBytes(j);
        expect(toHex(bf.decrypt(bf.encrypt(inp))), equals(toHex(inp)),
            reason: '[size: $j]');
      }
    });
    test('encrypt <-> decrypt (CTR)', () {
      for (int j = 0; j < 100; ++j) {
        final key = randomBytes((j % 56) + 1);
        final bf = Blowfish(key).ctr(randomBytes(8));
        final inp = randomBytes(j);
        expect(toHex(bf.decrypt(bf.encrypt(inp))), equals(toHex(inp)),
            reason: '[size: $j]');
      }
    });
  });

  group('counter increment', () {
    // CTR keystream blocks must match the ECB encryption of counter blocks
    test('carry crosses the 32-bit boundary', () {
      final key = randomBytes(16);
      final iv = fromHex('00000001FFFFFFFF');
      final ecb = Blowfish.noPadding(key).ecb();
      final k0 = ecb.encrypt(fromHex('00000001FFFFFFFF'));
      final k1 = ecb.encrypt(fromHex('0000000200000000'));
      final out = Blowfish(key).ctr(iv).encrypt(Uint8List(16));
      expect(toHex(out), equals(toHex([...k0, ...k1])));
    });
    test('carry is discarded beyond the counter bits', () {
      final key = randomBytes(16);
      final iv = fromHex('00000001FFFFFFFF');
      final ecb = Blowfish.noPadding(key).ecb();
      final k0 = ecb.encrypt(fromHex('00000001FFFFFFFF'));
      final k1 = ecb.encrypt(fromHex('00000001FFFFE000'));
      final out = Blowfish(key).ctr(iv, 13).encrypt(Uint8List(16));
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
      final bf = Blowfish(key).ecb();
      final enc =
          await bf.encryptor.bind(chunked(inp)).expand((x) => x).toList();
      expect(enc, equals(bf.encrypt(inp)));
      final dec =
          await bf.decryptor.bind(chunked(enc)).expand((x) => x).toList();
      expect(dec, equals(inp));
    });

    test('bind output matches convert output (CBC)', () async {
      final key = randomBytes(16);
      final inp = randomBytes(100);
      final bf = Blowfish(key).cbc(randomBytes(8));
      final enc =
          await bf.encryptor.bind(chunked(inp)).expand((x) => x).toList();
      expect(enc, equals(bf.encrypt(inp)));
      final dec =
          await bf.decryptor.bind(chunked(enc)).expand((x) => x).toList();
      expect(dec, equals(inp));
    });

    test('bind output matches convert output (CTR)', () async {
      final key = randomBytes(16);
      final inp = randomBytes(100);
      final bf = Blowfish(key).ctr(randomBytes(8));
      final enc =
          await bf.encryptor.bind(chunked(inp)).expand((x) => x).toList();
      expect(enc, equals(bf.encrypt(inp)));
      final dec =
          await bf.decryptor.bind(chunked(enc)).expand((x) => x).toList();
      expect(dec, equals(inp));
    });

    test('bind emits independent full chunks', () async {
      final key = randomBytes(16);
      final inp = randomBytes(64);
      final bf = Blowfish.noPadding(key).ecb();
      final chunks = await bf.encryptor.bind(chunked(inp)).toList();
      final again = bf.encrypt(inp);
      expect(chunks.expand((x) => x).toList(), equals(again));
      // mutating one chunk must not affect another
      chunks[0][0] ^= 0xFF;
      expect(chunks.expand((x) => x).toList(), isNot(equals(again)));
    });

    test('bind throws on invalid input size without padding', () {
      final bf = Blowfish.noPadding(randomBytes(16));
      final iv = randomBytes(8);
      final inp = randomBytes(9);
      expect(bf.ecb().encryptor.bind(chunked(inp)).drain<void>(),
          throwsStateError);
      expect(bf.ecb().decryptor.bind(chunked(inp)).drain<void>(),
          throwsStateError);
      expect(bf.cbc(iv).encryptor.bind(chunked(inp)).drain<void>(),
          throwsStateError);
      expect(bf.cbc(iv).decryptor.bind(chunked(inp)).drain<void>(),
          throwsStateError);
    });

    test('cast is unsupported for StreamCipher', () {
      final bf = Blowfish(Uint8List(16));
      expect(() => bf.ecb().encryptor.cast(), throwsUnsupportedError);
      expect(
          () => bf.cbc(Uint8List(8)).encryptor.cast(), throwsUnsupportedError);
      expect(
          () => bf.ctr(Uint8List(8)).encryptor.cast(), throwsUnsupportedError);
    });
  });
}
