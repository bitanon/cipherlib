// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';
import 'package:test/test.dart';

void main() {
  group('validation', () {
    final key = Uint8List(16);
    final nonce = Uint8List(13);

    test('name is correct', () {
      expect(AES(key).ccm(nonce).name, 'AES/CCM/NoPadding');
      expect(AES(key).ccm(nonce).encryptor.name, 'AES#encrypt/CCM/NoPadding');
      expect(AES(key).ccm(nonce).decryptor.name, 'AES#decrypt/CCM/NoPadding');
    });

    test('key must be 16, 24, or 32 bytes', () {
      expect(() => AES(Uint8List(0)).ccm(nonce), throwsStateError);
      expect(() => AES(Uint8List(15)).ccm(nonce), throwsStateError);
      expect(() => AES(Uint8List(16)).ccm(nonce), returnsNormally);
      expect(() => AES(Uint8List(24)).ccm(nonce), returnsNormally);
      expect(() => AES(Uint8List(32)).ccm(nonce), returnsNormally);
      expect(() => AES(Uint8List(33)).ccm(nonce), throwsStateError);
    });

    test('nonce must be between 7 and 13 bytes', () {
      expect(() => AES(key).ccm(Uint8List(6)), throwsStateError);
      expect(() => AES(key).ccm(Uint8List(7)), returnsNormally);
      expect(() => AES(key).ccm(Uint8List(13)), returnsNormally);
      expect(() => AES(key).ccm(Uint8List(14)), throwsStateError);
    });

    test('tagSize must be even and within 4..16', () {
      for (int i = 0; i < 20; ++i) {
        if (i >= 4 && i <= 16 && (i & 1) == 0) {
          expect(() => AES(key).ccm(nonce, tagSize: i), returnsNormally);
        } else {
          expect(() => AES(key).ccm(nonce, tagSize: i), throwsStateError);
        }
      }
    });

    test('decrypt fails when input shorter than tag', () {
      expect(() => AES(key).ccm(nonce).decrypt([1, 2, 3]), throwsStateError);
    });

    test('random nonce is used if not provided', () {
      final aes = AESInCCMMode(key);
      expect(aes.iv.length, 13);
      final inp = randomBytes(24);
      expect(aes.decrypt(aes.encrypt(inp)), equals(inp));
    });

    test('supports large additional authenticated data', () {
      // AAD of 0xFF00 bytes and above uses the extended length encoding
      for (final n in [0xFEFF, 0xFF00, 0x10000]) {
        final aes = AES(key).ccm(nonce, aad: Uint8List(n), tagSize: 8);
        final inp = randomBytes(24);
        expect(aes.decrypt(aes.encrypt(inp)), equals(inp), reason: '[aad: $n]');
      }
    });

    test('message must fit in the length field', () {
      // RFC 3610: a 13-byte nonce leaves L=2, limiting messages to 2^16 - 1
      final aes = AES(key).ccm(nonce, tagSize: 4);
      expect(() => aes.encrypt(Uint8List(65535)), returnsNormally);
      expect(() => aes.encrypt(Uint8List(65536)), throwsStateError);
      expect(() => aes.decrypt(Uint8List(65536 + 4)), throwsStateError);
    });

    test('reset iv', () {
      final aes = AES(key).ccm(Uint8List.fromList(randomBytes(13)));
      for (int j = 0; j < 25; ++j) {
        aes.resetIV();
        final inp = randomBytes(j);
        final cipher = aes.encrypt(inp);
        final plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
  });

  // RFC 3610 test vectors use:
  // - 13-byte nonce (L=2)
  // - clear header as AAD
  // - output packet = header || ciphertext || tag
  group('RFC 3610 vectors', () {
    test('packet vector #1 (M=8, header=8)', () {
      final key = fromHex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf');
      final nonce = fromHex('00000003020100a0a1a2a3a4a5');
      final aad = fromHex('0001020304050607');
      final plain = fromHex(
        '08090a0b0c0d0e0f101112131415161718191a1b1c1d1e',
      );
      final cipher = fromHex(
        '588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0',
      );

      final aes = AES(key).ccm(nonce, aad: aad, tagSize: 8);
      expect(toHex(aes.encrypt(plain)), equals(toHex(cipher)));
      expect(toHex(aes.decrypt(cipher)), equals(toHex(plain)));
    });

    test('packet vector #7 (M=10, header=8)', () {
      final key = fromHex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf');
      final nonce = fromHex('00000009080706a0a1a2a3a4a5');
      final aad = fromHex('0001020304050607');
      final plain = fromHex(
        '08090a0b0c0d0e0f101112131415161718191a1b1c1d1e',
      );
      final cipher = fromHex(
        '0135d1b2c95f41d5d1d4fec185d166b8094e999dfed96c048c56602c97acbb7490',
      );

      final aes = AES(key).ccm(nonce, aad: aad, tagSize: 10);
      expect(toHex(aes.encrypt(plain)), equals(toHex(cipher)));
      expect(toHex(aes.decrypt(cipher)), equals(toHex(plain)));
    });

    test('packet vector #13 (M=8, header=8)', () {
      final key = fromHex('d7828d13b2b0bdc325a76236df93cc6b');
      final nonce = fromHex('00412b4ea9cdbe3c9696766cfa');
      final aad = fromHex('0be1a88bace018b1');
      final plain = fromHex(
        '08e8cf97d820ea258460e96ad9cf5289054d895ceac47c',
      );
      final cipher = fromHex(
        '4cb97f86a2a4689a877947ab8091ef5386a6ffbdd080f8e78cf7cb0cddd7b3',
      );

      final aes = AES(key).ccm(nonce, aad: aad, tagSize: 8);
      expect(toHex(aes.encrypt(plain)), equals(toHex(cipher)));
      expect(toHex(aes.decrypt(cipher)), equals(toHex(plain)));
    });
  });

  group('stream cipher', () {
    test('encryptor bind matches convert with chunked input', () async {
      final key = fromHex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf');
      final nonce = fromHex('00000003020100a0a1a2a3a4a5');
      final aad = fromHex('0001020304050607');
      final plain = fromHex(
        '08090a0b0c0d0e0f101112131415161718191a1b1c1d1e',
      );
      final aes = AES(key).ccm(nonce, aad: aad, tagSize: 8);
      final chunked = <List<int>>[
        plain.sublist(0, 5),
        plain.sublist(5, 14),
        plain.sublist(14),
      ];

      final actual = await aes.encryptor
          .bind(Stream<List<int>>.fromIterable(chunked))
          .expand((x) => x)
          .toList();
      expect(actual, equals(aes.encrypt(plain)));
    });

    test('decryptor bind matches convert with chunked input', () async {
      final key = fromHex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf');
      final nonce = fromHex('00000003020100a0a1a2a3a4a5');
      final aad = fromHex('0001020304050607');
      final plain = fromHex(
        '08090a0b0c0d0e0f101112131415161718191a1b1c1d1e',
      );
      final aes = AES(key).ccm(nonce, aad: aad, tagSize: 8);
      final sealed = aes.encrypt(plain);

      final actual = await aes.decryptor
          .bind(Stream<List<int>>.fromIterable([
            sealed.sublist(0, 4),
            sealed.sublist(4, 17),
            sealed.sublist(17),
          ]))
          .expand((x) => x)
          .toList();

      expect(actual, equals(plain));
      expect(actual, equals(aes.decrypt(sealed)));
    });

    test('decryptor bind throws on invalid authentication tag', () async {
      final aes = AES(randomBytes(16)).ccm(randomBytes(13), tagSize: 8);
      final sealed = aes.encrypt(randomBytes(39));
      sealed[sealed.length - 1] ^= 1;
      expect(
        aes.decryptor
            .bind(Stream<List<int>>.fromIterable([
              sealed.sublist(0, 7),
              sealed.sublist(7),
            ]))
            .drain<void>(),
        throwsStateError,
      );
    });
  });
}
