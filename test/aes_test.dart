// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:cipherlib/cipherlib.dart';

void main() {
  group('AES Tests', () {
    // Sample key (32 bytes for AES-256)
    final key = List<int>.generate(32, (i) => i);

    // Sample initialization vector (IV) (16 bytes)
    final iv = List<int>.generate(16, (i) => i + 1);

    // Sample plaintext
    final plaintext = List<int>.generate(23, (i) => i + 2);

    test('AES no padding', () {
      final aes = AES.noPadding(key);
      final cbc = aes.cbc(iv);
      final input = List<int>.generate(32, (i) => i + 3);
      final ciphertext = cbc.encrypt(input);
      final decrypted = cbc.decrypt(ciphertext);
      expect(decrypted, equals(input));
    });

    test('AES byte padding', () {
      final aes = AES.byte(key);
      final cbc = aes.cbc(iv);
      final ciphertext = cbc.encrypt(plaintext);
      final decrypted = cbc.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES ANSI padding', () {
      final aes = AES.ansi(key);
      final cbc = aes.cbc(iv);
      final ciphertext = cbc.encrypt(plaintext);
      final decrypted = cbc.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES PKCS7 padding', () {
      final aes = AES.pkcs7(key);
      final cbc = aes.cbc(iv);
      final ciphertext = cbc.encrypt(plaintext);
      final decrypted = cbc.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES ECB Mode', () {
      final aes = AES(key);
      final ecb = aes.ecb();
      final ciphertext = ecb.encrypt(plaintext);
      final decrypted = ecb.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES CBC Mode', () {
      final aes = AES(key);
      final cbc = aes.cbc(iv);
      final ciphertext = cbc.encrypt(plaintext);
      final decrypted = cbc.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES CTR Mode', () {
      final aes = AES(key);
      final ctr = aes.ctr(iv);
      final ciphertext = ctr.encrypt(plaintext);
      final decrypted = ctr.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES CFB Mode', () {
      final aes = AES(key);
      final cfb = aes.cfb(iv);
      final ciphertext = cfb.encrypt(plaintext);
      final decrypted = cfb.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES CFB-8 Mode', () {
      final aes = AES(key);
      final cfb = aes.cfb8(iv);
      final ciphertext = cfb.encrypt(plaintext);
      final decrypted = cfb.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES CFB-64 Mode', () {
      final aes = AES(key);
      final cfb = aes.cfb64(iv);
      final ciphertext = cfb.encrypt(plaintext);
      final decrypted = cfb.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES CFB-128 Mode', () {
      final aes = AES(key);
      final cfb = aes.cfb128(iv);
      final ciphertext = cfb.encrypt(plaintext);
      final decrypted = cfb.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES OFB Mode', () {
      final aes = AES(key);
      final ofb = aes.ofb(iv);
      final ciphertext = ofb.encrypt(plaintext);
      final decrypted = ofb.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES OFB-8 Mode', () {
      final aes = AES(key);
      final ofb = aes.ofb8(iv);
      final ciphertext = ofb.encrypt(plaintext);
      final decrypted = ofb.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES OFB-64 Mode', () {
      final aes = AES(key);
      final ofb = aes.ofb64(iv);
      final ciphertext = ofb.encrypt(plaintext);
      final decrypted = ofb.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES OFB-128 Mode', () {
      final aes = AES(key);
      final ofb = aes.ofb128(iv);
      final ciphertext = ofb.encrypt(plaintext);
      final decrypted = ofb.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES PCBC Mode', () {
      final aes = AES(key);
      final pcbc = aes.pcbc(iv);
      final ciphertext = pcbc.encrypt(plaintext);
      final decrypted = pcbc.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES GCM Mode', () {
      final aes = AES(key);
      final gcm = aes.gcm(iv);
      final ciphertext = gcm.encrypt(plaintext);
      final decrypted = gcm.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES XTS Mode', () {
      final aes = AES(key);
      final xts = aes.xts(iv);
      final ciphertext = xts.encrypt(plaintext);
      final decrypted = xts.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('AES IGE Mode', () {
      final aes = AES(key);
      final ige = aes.ige(iv);
      final ciphertext = ige.encrypt(plaintext);
      final decrypted = ige.decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });
  });
}
