// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';
import 'package:test/test.dart';

void main() {
  final key = Uint8List(32);
  final iv = Uint8List(16);
  final input = Uint8List(64);
  test("name is correct", () {
    expect(AES.noPadding(key).pcbc(iv).name, "AES/PCBC/NoPadding");
    expect(AES.ansi(key).pcbc(iv).name, "AES/PCBC/ANSI");
    expect(AES.byte(key).pcbc(iv).name, "AES/PCBC/Byte");
    expect(AES.pkcs7(key).pcbc(iv).name, "AES/PCBC/PKCS7");
  });
  test("padding is correct", () {
    expect(AES.noPadding(key).pcbc(iv).padding, Padding.none);
    expect(AES.ansi(key).pcbc(iv).padding, Padding.ansi);
    expect(AES.byte(key).pcbc(iv).padding, Padding.byte);
    expect(AES.pkcs7(key).pcbc(iv).padding, Padding.pkcs7);
  });
  test("accepts null IV", () {
    expect(() => AESInPCBCMode(key).encrypt(input), returnsNormally);
  });
  test("encryptor name is correct", () {
    expect(AES.noPadding(key).pcbc(iv).encryptor.name,
        "AES#encrypt/PCBC/NoPadding");
    expect(AES.ansi(key).pcbc(iv).encryptor.name, "AES#encrypt/PCBC/ANSI");
    expect(AES.byte(key).pcbc(iv).encryptor.name, "AES#encrypt/PCBC/Byte");
    expect(AES.pkcs7(key).pcbc(iv).encryptor.name, "AES#encrypt/PCBC/PKCS7");
  });
  test("decryptor name is correct", () {
    expect(AES.noPadding(key).pcbc(iv).decryptor.name,
        "AES#decrypt/PCBC/NoPadding");
    expect(AES.ansi(key).pcbc(iv).decryptor.name, "AES#decrypt/PCBC/ANSI");
    expect(AES.byte(key).pcbc(iv).decryptor.name, "AES#decrypt/PCBC/Byte");
    expect(AES.pkcs7(key).pcbc(iv).decryptor.name, "AES#decrypt/PCBC/PKCS7");
  });
  test('throws error on invalid input size', () {
    var aes = AES.noPadding(Uint8List(16)).pcbc(Uint8List(16));
    expect(() => aes.encrypt(Uint8List(10)), throwsStateError);
    expect(() => aes.decrypt(Uint8List(10)), throwsStateError);
    expect(() => aes.encrypt(Uint8List(17)), throwsStateError);
    expect(() => aes.decrypt(Uint8List(17)), throwsStateError);
  });
  test('throws error on invalid salt size', () {
    var aes = AES(Uint8List(16));
    expect(() => aes.pcbc(Uint8List(15)).encrypt([0]), throwsStateError);
    expect(() => aes.pcbc(Uint8List(8)).decrypt([0]), throwsStateError);
    expect(aes.pcbc(Uint8List(16)).encrypt([]).length, 16);
  });
  test('no padding returns exact block length', () {
    final plain = Uint8List.fromList(List<int>.generate(16, (i) => i));
    final out = AES.noPadding(key).pcbc(iv).encrypt(plain);
    expect(out.length, equals(16));
  });
  test('reset iv', () {
    var iv = randomBytes(16);
    var key = randomBytes(24);
    var aes = AES(key).pcbc(iv);
    for (int j = 0; j < 100; j++) {
      aes.resetIV();
      var inp = randomBytes(j);
      var cipher = aes.encrypt(inp);
      var plain = aes.decrypt(cipher);
      expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
    }
  });

  group('stream cipher', () {
    test('encryptor bind matches convert with chunked input', () async {
      final key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
      final iv = fromHex('000102030405060708090a0b0c0d0e0f');
      final plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef',
      );
      final aes = AES.pkcs7(key).pcbc(iv);
      final chunked = <List<int>>[
        plain.sublist(0, 7),
        plain.sublist(7, 23),
        plain.sublist(23, 44),
        plain.sublist(44),
      ];

      final actual = await aes.encryptor
          .bind(Stream<List<int>>.fromIterable(chunked))
          .expand((x) => x)
          .toList();

      expect(actual, equals(aes.encrypt(plain)));
    });

    test('decryptor bind matches convert with chunked input', () async {
      final key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
      final iv = fromHex('000102030405060708090a0b0c0d0e0f');
      final plain = fromHex(
        '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411e5fbc1191a0a52ef',
      );
      final aes = AES.pkcs7(key).pcbc(iv);
      final cipher = aes.encrypt(plain);
      final chunked = <List<int>>[
        cipher.sublist(0, 5),
        cipher.sublist(5, 19),
        cipher.sublist(19, 41),
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
      final aes = AES.noPadding(Uint8List(16)).pcbc(Uint8List(16));
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
      final aes = AES.pkcs7(Uint8List(16)).pcbc(Uint8List(16));
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
