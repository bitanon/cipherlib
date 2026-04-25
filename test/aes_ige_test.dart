// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/random.dart';
import 'package:cipherlib/codecs.dart';
import 'package:test/test.dart';

void main() {
  final key = Uint8List(32);
  final iv = Uint8List(16);
  final input = Uint8List(64);
  test("name is correct", () {
    expect(AES.noPadding(key).ige(iv).name, "AES/IGE/NoPadding");
    expect(AES.ansi(key).ige(iv).name, "AES/IGE/ANSI");
    expect(AES.byte(key).ige(iv).name, "AES/IGE/Byte");
    expect(AES.pkcs7(key).ige(iv).name, "AES/IGE/PKCS7");
  });
  test("padding is correct", () {
    expect(AES.noPadding(key).ige(iv).padding, Padding.none);
    expect(AES.ansi(key).ige(iv).padding, Padding.ansi);
    expect(AES.byte(key).ige(iv).padding, Padding.byte);
    expect(AES.pkcs7(key).ige(iv).padding, Padding.pkcs7);
  });
  test("accepts null IV", () {
    expect(() => AESInIGEMode(key).encrypt(input), returnsNormally);
  });
  test("encryptor name is correct", () {
    expect(
        AES.noPadding(key).ige(iv).encryptor.name, "AES#encrypt/IGE/NoPadding");
    expect(AES.ansi(key).ige(iv).encryptor.name, "AES#encrypt/IGE/ANSI");
    expect(AES.byte(key).ige(iv).encryptor.name, "AES#encrypt/IGE/Byte");
    expect(AES.pkcs7(key).ige(iv).encryptor.name, "AES#encrypt/IGE/PKCS7");
  });
  test("decryptor name is correct", () {
    expect(
        AES.noPadding(key).ige(iv).decryptor.name, "AES#decrypt/IGE/NoPadding");
    expect(AES.ansi(key).ige(iv).decryptor.name, "AES#decrypt/IGE/ANSI");
    expect(AES.byte(key).ige(iv).decryptor.name, "AES#decrypt/IGE/Byte");
    expect(AES.pkcs7(key).ige(iv).decryptor.name, "AES#decrypt/IGE/PKCS7");
  });
  test('reset iv', () {
    var iv = randomBytes(32);
    var key = randomBytes(24);
    var aes = AES(key).ige(iv);
    for (int j = 0; j < 100; j++) {
      aes.resetIV();
      var inp = randomBytes(j);
      var cipher = aes.encrypt(inp);
      var plain = aes.decrypt(cipher);
      expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
    }
  });
  test('throws error on invalid key size', () {
    expect(() => AESInIGEMode(Uint8List(15)).encrypt(input), throwsStateError);
    expect(() => AESInIGEMode(Uint8List(17)).encrypt(input), throwsStateError);
    expect(() => AESInIGEMode(Uint8List(23)).encrypt(input), throwsStateError);
    expect(() => AESInIGEMode(Uint8List(25)).encrypt(input), throwsStateError);
    expect(() => AESInIGEMode(Uint8List(31)).encrypt(input), throwsStateError);
    expect(() => AESInIGEMode(Uint8List(33)).encrypt(input), throwsStateError);
  });
  test('throws error on invalid input size', () {
    var aes = AES.noPadding(Uint8List(16)).ige(Uint8List(32));
    expect(() => aes.encrypt(Uint8List(10)), throwsStateError);
    expect(() => aes.decrypt(Uint8List(10)), throwsStateError);
    expect(() => aes.encrypt(Uint8List(17)), throwsStateError);
    expect(() => aes.decrypt(Uint8List(17)), throwsStateError);
  });
  test('throws error on invalid salt size', () {
    var aes = AES(Uint8List(16));
    expect(() => aes.ige(Uint8List(0)).decrypt([0]), throwsStateError);
    expect(() => aes.ige(Uint8List(15)).encrypt([0]), throwsStateError);
    expect(aes.ige(Uint8List(16)).encrypt([]).length, 16);
  });

  group('empty message', () {
    var aes = AES.noPadding(Uint8List(32)).ige(Uint8List(32));
    test('encrypt', () {
      var actual = aes.encrypt([]);
      expect(toHex(actual), equals(toHex([])));
    });
    test('decrypt', () {
      var reverse = aes.decrypt([]);
      expect(toHex(reverse), equals(toHex([])));
    });
  });

  group('stream cipher', () {
    test('encryptor bind matches convert with chunked input', () async {
      final key = randomBytes(32);
      final iv = randomBytes(32);
      final plain = randomBytes(47);
      final aes = AES.pkcs7(key).ige(iv);
      final chunked = <List<int>>[
        plain.sublist(0, 5),
        plain.sublist(5, 22),
        plain.sublist(22, 39),
        plain.sublist(39),
      ];

      final actual = await aes.encryptor
          .bind(Stream<List<int>>.fromIterable(chunked))
          .expand((x) => x)
          .toList();

      expect(actual, equals(aes.encrypt(plain)));
    });

    test('decryptor bind matches convert with chunked input', () async {
      final key = randomBytes(32);
      final iv = randomBytes(32);
      final plain = randomBytes(47);
      final aes = AES.pkcs7(key).ige(iv);
      final cipher = aes.encrypt(plain);
      final chunked = <List<int>>[
        cipher.sublist(0, 3),
        cipher.sublist(3, 21),
        cipher.sublist(21, 41),
        cipher.sublist(41),
      ];

      final actual = await aes.decryptor
          .bind(Stream<List<int>>.fromIterable(chunked))
          .expand((x) => x)
          .toList();

      expect(actual, equals(aes.decrypt(cipher)));
      expect(actual, equals(plain));
    });

    test('encryptor bind throws on incomplete final block with no padding',
        () async {
      final aes = AES.noPadding(Uint8List(32)).ige(Uint8List(32));
      expect(
        aes.encryptor
            .bind(Stream<List<int>>.fromIterable([
              [1, 2, 3],
              [4, 5],
            ]))
            .drain<void>(),
        throwsStateError,
      );
    });

    test('decryptor bind throws on incomplete ciphertext block', () async {
      final aes = AES.pkcs7(Uint8List(32)).ige(Uint8List(32));
      expect(
        aes.decryptor
            .bind(Stream<List<int>>.fromIterable([
              [1, 2, 3],
              [4, 5],
            ]))
            .drain<void>(),
        throwsStateError,
      );
    });
  });
}
