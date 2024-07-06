// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/hashlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

void main() {
  group("encryption", () {
    test('128-bit with PKCS#7 padding', () {
      var inp = 'A not very secret message'.codeUnits;
      var key = 'abcdefghijklmnop'.codeUnits;
      var nonce = Int64.bytes('lka9JLKa'.codeUnits);
      var counter = Int64.bytes('sljkdPsd'.codeUnits);
      var expected = '047B37EBDE11A491CB3F7842E48E54F8326E293619E69BE24B';
      var actual = AES(key).ctr(nonce, counter).encrypt(inp);
      expect(toHex(actual, upper: true), equals(expected));
    });
    test('192-bit with PKCS#7 padding', () {
      var inp = 'A not very secret message'.codeUnits;
      var key = 'abcdefghijklmnopqrstuvwx'.codeUnits;
      var nonce = Int64.bytes('lka9JLKa'.codeUnits);
      var counter = Int64.bytes('sljkdPsd'.codeUnits);
      var expected = 'A85734374F88C90877C39D7A4C78177F5F80290F7E2F4B4B15';
      var actual = AES(key).ctr(nonce, counter).encrypt(inp);
      expect(toHex(actual, upper: true), equals(expected));
    });
    test('256-bit with PKCS#7 padding', () {
      var inp = 'A not very secret message'.codeUnits;
      var key = 'abcdefghijklmnopqrstuvwxyz012345'.codeUnits;
      var nonce = Int64.bytes('lka9JLKa'.codeUnits);
      var counter = Int64.bytes('sljkdPsd'.codeUnits);
      var expected = '05A2F1FF79461F903C9E9DE82FF710244D36E35AF3AA8B6695';
      var actual = AES(key).ctr(nonce, counter).encrypt(inp);
      expect(toHex(actual, upper: true), equals(expected));
    });
  });

  group("decryption", () {
    test('128-bit with PKCS#7 padding', () {
      var inp = fromHex('047B37EBDE11A491CB3F7842E48E54F8326E293619E69BE24B');
      var key = 'abcdefghijklmnop'.codeUnits;
      var nonce = Int64.bytes('lka9JLKa'.codeUnits);
      var counter = Int64.bytes('sljkdPsd'.codeUnits);
      var expected = 'A not very secret message';
      var actual = AES(key).ctr(nonce, counter).decrypt(inp);
      expect(String.fromCharCodes(actual), equals(expected));
    });
    test('192-bit with PKCS#7 padding', () {
      var inp = fromHex('A85734374F88C90877C39D7A4C78177F5F80290F7E2F4B4B15');
      var key = 'abcdefghijklmnopqrstuvwx'.codeUnits;
      var nonce = Int64.bytes('lka9JLKa'.codeUnits);
      var counter = Int64.bytes('sljkdPsd'.codeUnits);
      var expected = 'A not very secret message';
      var actual = AES(key).ctr(nonce, counter).decrypt(inp);
      expect(String.fromCharCodes(actual), equals(expected));
    });
    test('256-bit with PKCS#7 padding', () {
      var inp = fromHex('05A2F1FF79461F903C9E9DE82FF710244D36E35AF3AA8B6695');
      var key = 'abcdefghijklmnopqrstuvwxyz012345'.codeUnits;
      var nonce = Int64.bytes('lka9JLKa'.codeUnits);
      var counter = Int64.bytes('sljkdPsd'.codeUnits);
      var expected = 'A not very secret message';
      var actual = AES(key).ctr(nonce, counter).decrypt(inp);
      expect(String.fromCharCodes(actual), equals(expected));
    });
  });

  group('encryption <-> decryption', () {
    test("128-bit", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = Int64.random();
        var cipher = AES(key).ctr(iv).encrypt(inp);
        var plain = AES(key).ctr(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("192-bit", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = Int64.random();
        var cipher = AES(key).ctr(iv).encrypt(inp);
        var plain = AES(key).ctr(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("256-bit", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = Int64.random();
        var cipher = AES(key).ctr(iv).encrypt(inp);
        var plain = AES(key).ctr(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
  });

  group('sink test', () {
    test('encryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = Int64.random();
        final aes = AES(key).ctr(iv);

        var input = randomBytes(j);
        var cipher = aes.encrypt(input);

        var enc = aes.encryptor.createSink();
        var output = <int>[];
        for (int i = 0; i < input.length; i += 23) {
          output.addAll(enc.add(input.skip(i).take(23).toList()));
        }
        output.addAll(enc.close());
        expect(toHex(output), equals(toHex(cipher)), reason: '[size: $j]');

        var plain = aes.decrypt(output);
        expect(toHex(plain), equals(toHex(input)), reason: '[size: $j]');
      }
    });

    test('decryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = Int64.random();
        final aes = AES(key).ctr(iv);

        var input = randomBytes(j);
        var cipher = aes.encrypt(input);

        var dec = aes.decryptor.createSink();
        var output = <int>[];
        for (int i = 0; i < cipher.length; i += 23) {
          output.addAll(dec.add(cipher.skip(i).take(23).toList()));
        }
        output.addAll(dec.close());
        expect(toHex(output), equals(toHex(input)), reason: '[size: $j]');
      }
    });
  });

  test('reset nonce', () {
    var iv = Int64.random();
    var key = randomBytes(24);
    var aes = AES(key).ctr(iv);
    for (int j = 0; j < 100; j++) {
      aes.resetNonce();
      var inp = randomBytes(j);
      var cipher = aes.encrypt(inp);
      var plain = aes.decrypt(cipher);
      expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
    }
  });
  test('reset counter', () {
    var iv = Int64.random();
    var key = randomBytes(24);
    var aes = AES(key).ctr(iv);
    for (int j = 0; j < 100; j++) {
      aes.resetCounter();
      var inp = randomBytes(j);
      var cipher = aes.encrypt(inp);
      var plain = aes.decrypt(cipher);
      expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
    }
  });
  test('reset nonce and counter', () {
    var iv = Int64.random();
    var key = randomBytes(24);
    var aes = AES(key).ctr(iv);
    for (int j = 0; j < 100; j++) {
      aes.resetNonce();
      aes.resetCounter();
      var inp = randomBytes(j);
      var cipher = aes.encrypt(inp);
      var plain = aes.decrypt(cipher);
      expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
    }
  });
}
