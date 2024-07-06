// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/src/algorithms/aes/_core.dart';
import 'package:hashlib/hashlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

void main() {
  group("key expansion", () {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
    test("128-bit", () {
      var key = fromHex(
        '2b7e151628aed2a6abf7158809cf4f3c',
      ).buffer.asUint32List();
      var expanded = Uint32List.fromList([
        0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, //
        0x88542cb1, 0x23a33939, 0x2a6c7605, 0xf2c295f2, 0x7a96b943,
        0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e, 0x1e237e44,
        0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
        0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a,
        0x110b3efd, 0xdbf98641, 0xca0093fd, 0x4e54f70e, 0x5f5fc9f3,
        0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560,
        0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
        0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6,
      ]);
      var res = AESCore.$expandEncryptionKey(key);
      expect(toHex(res), equals(toHex(expanded)));
    });
    test("192-bit", () {
      var key = fromHex(
        '8e73b0f7da0e6452c810f32b'
        '809079e562f8ead2522c6b7b',
      ).buffer.asUint32List();
      var expanded = Uint32List.fromList([
        0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, //
        0x522c6b7b, 0xfe0c91f7, 0x2402f5a5, 0xec12068e, 0x6c827f6b,
        0x0e7a95b9, 0x5c56fec2, 0x4db7b4bd, 0x69b54118, 0x85a74796,
        0xe92538fd, 0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f,
        0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6, 0xa25e7ed5,
        0x83b1cf9a, 0x27f93943, 0x6a94f767, 0xc0a69407, 0xd19da4e1,
        0xec1786eb, 0x6fa64971, 0x485f7032, 0x22cb8755, 0xe26d1352,
        0x33f0b7b3, 0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e,
        0xa7e1466c, 0x9411f1df, 0x821f750a, 0xad07d753, 0xca400538,
        0x8fcc5006, 0x282d166a, 0xbc3ce7b5, 0xe98ba06f, 0x448c773c,
        0x8ecc7204, 0x01002202,
      ]);
      var res = AESCore.$expandEncryptionKey(key);
      expect(toHex(res), equals(toHex(expanded)));
    });
    test("256-bit", () {
      var key = fromHex(
        '603deb1015ca71be2b73aef0857d7781'
        '1f352c073b6108d72d9810a30914dff4',
      ).buffer.asUint32List();
      var expanded = Uint32List.fromList([
        0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, //
        0x3b6108d7, 0x2d9810a3, 0x0914dff4, 0x9ba35411, 0x8e6925af,
        0xa51a8b5f, 0x2067fcde, 0xa8b09c1a, 0x93d194cd, 0xbe49846e,
        0xb75d5b9a, 0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96,
        0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3, 0x812c81ad,
        0xdadf48ba, 0x24360af2, 0xfab8b464, 0x98c5bfc9, 0xbebd198e,
        0x268c3ba7, 0x09e04214, 0x68007bac, 0xb2df3316, 0x96e939e4,
        0x6c518d80, 0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239,
        0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15, 0x5886ca5d,
        0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3, 0x749c47ab, 0x18501dda,
        0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34, 0x9adf6ace,
        0xbd10190d, 0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
      ]);
      var res = AESCore.$expandEncryptionKey(key);
      expect(toHex(res), equals(toHex(expanded)));
    });
  });

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
    test('PKCS#7 padding', () {
      var inp = 'A not very secret message'.codeUnits;
      var key = 'abcdefghijklmnop'.codeUnits;
      var expected =
          '9224D7A1B18964D1184F5E93B0EBEBD2A26031EF0E1C7F271298CBEC4351ABE8';
      var actual = aesEncrypt(inp, key);
      expect(toHex(actual, upper: true), equals(expected));
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
