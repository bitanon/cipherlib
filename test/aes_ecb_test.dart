// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/hashlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

void main() {
  group("encryption", () {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    test("128-bit NIST.FIPS.197-upd1", () {
      var key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
      var inp = fromHex('3243f6a8885a308d313198a2e0370734');
      var out = '3925841d02dc09fbdc118597196a0b32';
      var rr = AES.noPadding(key).ecb().encrypt(inp);
      expect(toHex(rr), equals(out));
    });
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core_All.pdf
    test("128-bit CSRC NIST example", () {
      var key = fromHex('2B7E151628AED2A6ABF7158809CF4F3C');
      var inp = fromHex('6BC1BEE22E409F96E93D7E117393172A'
          'AE2D8A571E03AC9C9EB76FAC45AF8E51'
          '30C81C46A35CE411E5FBC1191A0A52EF'
          'F69F2445DF4F9B17AD2B417BE66C3710');
      var out = '3AD77BB40D7A3660A89ECAF32466EF97'
          'F5D3D58503B9699DE785895A96FDBAAF'
          '43B1CD7F598ECE23881B00E3ED030688'
          '7B0C785E27E8AD3F8223207104725DD4';
      var rr = AES.noPadding(key).ecb().encrypt(inp);
      expect(toHex(rr, upper: true), equals(out));
    });
    test("192-bit CSRC NIST example", () {
      var key = fromHex('8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B');
      var inp = fromHex('6BC1BEE22E409F96E93D7E117393172A'
          'AE2D8A571E03AC9C9EB76FAC45AF8E51'
          '30C81C46A35CE411E5FBC1191A0A52EF'
          'F69F2445DF4F9B17AD2B417BE66C3710');
      var out = 'BD334F1D6E45F25FF712A214571FA5CC'
          '974104846D0AD3AD7734ECB3ECEE4EEF'
          'EF7AFD2270E2E60ADCE0BA2FACE6444E'
          '9A4B41BA738D6C72FB16691603C18E0E';
      var rr = AES.noPadding(key).ecb().encrypt(inp);
      expect(toHex(rr, upper: true), equals(out));
    });
    test("256-bit CSRC NIST example", () {
      var key = fromHex('603DEB1015CA71BE2B73AEF0857D7781'
          '1F352C073B6108D72D9810A30914DFF4');
      var inp = fromHex('6BC1BEE22E409F96E93D7E117393172A'
          'AE2D8A571E03AC9C9EB76FAC45AF8E51'
          '30C81C46A35CE411E5FBC1191A0A52EF'
          'F69F2445DF4F9B17AD2B417BE66C3710');
      var out = 'F3EED1BDB5D2A03C064B5A7E3DB181F8'
          '591CCB10D410ED26DC5BA74A31362870'
          'B6ED21B99CA6F4F9F153E7B1BEAFED1D'
          '23304B7A39F9F3FF067D8D8F9E24ECC7';
      var rr = AES.noPadding(key).ecb().encrypt(inp);
      expect(toHex(rr, upper: true), equals(out));
    });
    test('128-bit with PKCS#7 padding', () {
      var inp = 'A not very secret message'.codeUnits;
      var key = 'abcdefghijklmnop'.codeUnits;
      var expected =
          '9224d7a1b18964d1184f5e93b0ebebd2a26031ef0e1c7f271298cbec4351abe8';
      var actual = AES(key).ecb().encrypt(inp);
      expect(toHex(actual), equals(expected));
    });
    test('192-bit with PKCS#7 padding', () {
      var inp = 'A not very secret message'.codeUnits;
      var key = 'abcdefghijklmnopqrstuvwx'.codeUnits;
      var expected =
          '4520a2df64b588535d95d14625fe6f66e36c07bfb712b1f1dbf9e88f9c4ec2db';
      var actual = AES(key).ecb().encrypt(inp);
      expect(toHex(actual), equals(expected));
    });
    test('256-bit with PKCS#7 padding', () {
      var inp = 'A not very secret message'.codeUnits;
      var key = 'abcdefghijklmnopqrstuvwxyz012345'.codeUnits;
      var expected =
          '09f1ff0aeb92b79274ac55abdc074a0198e1a6fb59c3177fb56ed1d75bc424e3';
      var actual = AES(key).ecb().encrypt(inp);
      expect(toHex(actual), equals(expected));
    });
    test('throws error on invalid input size', () {
      var key = Uint32List(16);
      var inp = Uint32List(10);
      expect(() => AES.noPadding(key).ecb().encrypt(inp), throwsStateError);
    });
  });

  group("decryption", () {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    test("128-bit NIST.FIPS.197-upd1", () {
      var key = fromHex('2B7E151628AED2A6ABF7158809CF4F3C');
      var inp = fromHex('3925841d02dc09fbdc118597196a0b32');
      var out = '3243f6a8885a308d313198a2e0370734';
      var rr = AES.noPadding(key).ecb().decrypt(inp);
      expect(toHex(rr), equals(out));
    });
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core_All.pdf
    test("128-bit CSRC NIST example", () {
      var key = fromHex('2B7E151628AED2A6ABF7158809CF4F3C');
      var inp = fromHex('3AD77BB40D7A3660A89ECAF32466EF97'
          'F5D3D58503B9699DE785895A96FDBAAF'
          '43B1CD7F598ECE23881B00E3ED030688'
          '7B0C785E27E8AD3F8223207104725DD4');
      var out = '6BC1BEE22E409F96E93D7E117393172A'
          'AE2D8A571E03AC9C9EB76FAC45AF8E51'
          '30C81C46A35CE411E5FBC1191A0A52EF'
          'F69F2445DF4F9B17AD2B417BE66C3710';
      var rr = AES.noPadding(key).ecb().decrypt(inp);
      expect(toHex(rr, upper: true), equals(out));
    });
    test("192-bit CSRC NIST example", () {
      var key = fromHex('8E73B0F7DA0E6452C810F32B809079E5'
          '62F8EAD2522C6B7B');
      var inp = fromHex('BD334F1D6E45F25FF712A214571FA5CC'
          '974104846D0AD3AD7734ECB3ECEE4EEF'
          'EF7AFD2270E2E60ADCE0BA2FACE6444E'
          '9A4B41BA738D6C72FB16691603C18E0E');
      var out = '6BC1BEE22E409F96E93D7E117393172A'
          'AE2D8A571E03AC9C9EB76FAC45AF8E51'
          '30C81C46A35CE411E5FBC1191A0A52EF'
          'F69F2445DF4F9B17AD2B417BE66C3710';
      var rr = AES.noPadding(key).ecb().decrypt(inp);
      expect(toHex(rr, upper: true), equals(out));
    });
    test("256-bit CSRC NIST example", () {
      var key = fromHex('603DEB1015CA71BE2B73AEF0857D7781'
          '1F352C073B6108D72D9810A30914DFF4');
      var inp = fromHex('F3EED1BDB5D2A03C064B5A7E3DB181F8'
          '591CCB10D410ED26DC5BA74A31362870'
          'B6ED21B99CA6F4F9F153E7B1BEAFED1D'
          '23304B7A39F9F3FF067D8D8F9E24ECC7');
      var out = '6BC1BEE22E409F96E93D7E117393172A'
          'AE2D8A571E03AC9C9EB76FAC45AF8E51'
          '30C81C46A35CE411E5FBC1191A0A52EF'
          'F69F2445DF4F9B17AD2B417BE66C3710';
      var rr = AES.noPadding(key).ecb().decrypt(inp);
      expect(toHex(rr, upper: true), equals(out));
    });
    test('128-bit with PKCS#7 padding', () {
      var inp = fromHex('9224d7a1b18964d1184f5e93b0ebebd2a'
          '26031ef0e1c7f271298cbec4351abe8');
      var key = 'abcdefghijklmnop'.codeUnits;
      var expected = 'A not very secret message';
      var actual = AES(key).ecb().decrypt(inp);
      expect(String.fromCharCodes(actual), equals(expected));
    });
    test('192-bit with PKCS#7 padding', () {
      var inp = fromHex(
          '4520a2df64b588535d95d14625fe6f66e36c07bfb712b1f1dbf9e88f9c4ec2db');
      var key = 'abcdefghijklmnopqrstuvwx'.codeUnits;
      var expected = 'A not very secret message';
      var actual = AES(key).ecb().decrypt(inp);
      expect(String.fromCharCodes(actual), equals(expected));
    });
    test('256-bit with PKCS#7 padding', () {
      var inp = fromHex(
          '09f1ff0aeb92b79274ac55abdc074a0198e1a6fb59c3177fb56ed1d75bc424e3');
      var key = 'abcdefghijklmnopqrstuvwxyz012345'.codeUnits;
      var expected = 'A not very secret message';
      var actual = AES(key).ecb().decrypt(inp);
      expect(String.fromCharCodes(actual), equals(expected));
    });
    test('throws error on invalid input size', () {
      var key = Uint32List(16);
      var inp = Uint32List(10);
      expect(() => AES.noPadding(key).ecb().decrypt(inp), throwsStateError);
    });
  });

  group('encryption <-> decryption', () {
    test("128-bit", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var input = randomBytes(j);
        var bytes = Uint8List.fromList(input);
        var cipher = AES(key).ecb().encrypt(input);
        var plain = AES(key).ecb().decrypt(cipher);
        expect(toHex(bytes), equals(toHex(plain)), reason: '[size: $j]');
      }
    });
    test("192-bit", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var input = randomBytes(j);
        var bytes = Uint8List.fromList(input);
        var cipher = AES(key).ecb().encrypt(input);
        var plain = AES(key).ecb().decrypt(cipher);
        expect(toHex(bytes), equals(toHex(plain)), reason: '[size: $j]');
      }
    });
    test("256-bit", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var input = randomBytes(j);
        var bytes = Uint8List.fromList(input);
        var cipher = AES(key).ecb().encrypt(input);
        var plain = AES(key).ecb().decrypt(cipher);
        expect(toHex(bytes), equals(toHex(plain)), reason: '[size: $j]');
      }
    });
  });

  group('sink test', () {
    test('encryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        final aes = AES(key).ecb();

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
        var input = randomBytes(j);
        var cipher = AES(key).ecb().encrypt(input);

        var dec = AES(key).ecb().decryptor.createSink();
        var output = <int>[];
        for (int i = 0; i < cipher.length; i += 23) {
          output.addAll(dec.add(cipher.skip(i).take(23).toList()));
        }
        output.addAll(dec.close());
        expect(toHex(output), equals(toHex(input)), reason: '[size: $j]');
      }
    });
  });
}
