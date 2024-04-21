// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aes.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

void main() {
  group('Test AES cipher', () {
    group("encryption key expansion", () {
      // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core_All.pdf
      test("128-bit", () {
        var key = Uint32List.fromList([
          0x2b7e1516,
          0x28aed2a6,
          0xabf71588,
          0x09cf4f3c,
        ]);
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
        var res = AES.$expandKey(key);
        print(toHex(key.buffer.asUint8List()));
        expect(res, equals(expanded));
      });
      test("192-bit", () {
        var key = Uint32List.fromList([
          0x8e73b0f7,
          0xda0e6452,
          0xc810f32b,
          0x809079e5,
          0x62f8ead2,
          0x522c6b7b,
        ]);
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
        var res = AES.$expandKey(key);
        expect(res, equals(expanded));
      });
      test("256-bit", () {
        var key = Uint32List.fromList([
          0x603deb10,
          0x15ca71be,
          0x2b73aef0,
          0x857d7781,
          0x1f352c07,
          0x3b6108d7,
          0x2d9810a3,
          0x0914dff4,
        ]);
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
        var res = AES.$expandKey(key);
        expect(res, equals(expanded));
      });
    });
    group("encryption", () {
      test("128-bit NIST.FIPS.197-upd1", () {
        var key = Uint32List.fromList([
          0x2b7e1516,
          0x28aed2a6,
          0xabf71588,
          0x09cf4f3c,
        ]).buffer.asUint8List();
        var inp = Uint32List.fromList([
          0x3243f6a8,
          0x885a308d,
          0x313198a2,
          0xe0370734,
        ]).buffer.asUint8List();
        var out = Uint32List.fromList([
          0x3925841d,
          0x02dc09fb,
          0xdc118597,
          0x196a0b32,
        ]).buffer.asUint8List();
        var rr = AES(key).convert(inp);
        expect(rr, equals(out));
      });
      test("128-bit CSRC NIST example", () {
        var key = Uint32List.fromList([
          0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C, //
        ]).buffer.asUint8List();
        var inp = Uint32List.fromList([
          0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, //
          0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,
          0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF,
          0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710
        ]).buffer.asUint8List();
        var out = Uint32List.fromList([
          0x3AD77BB4, 0x0D7A3660, 0xA89ECAF3, 0x2466EF97, //
          0xF5D3D585, 0x03B9699D, 0xE785895A, 0x96FDBAAF,
          0x43B1CD7F, 0x598ECE23, 0x881B00E3, 0xED030688,
          0x7B0C785E, 0x27E8AD3F, 0x82232071, 0x04725DD4,
        ]).buffer.asUint8List();
        var rr = AES(key).convert(inp);
        expect(rr, equals(out));
      });
      test("192-bit CSRC NIST example", () {
        var key = Uint32List.fromList([
          0x8E73B0F7, 0xDA0E6452, 0xC810F32B, 0x809079E5, //
          0x62F8EAD2, 0x522C6B7B,
        ]).buffer.asUint8List();
        var inp = Uint32List.fromList([
          0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, //
          0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,
          0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF,
          0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710
        ]).buffer.asUint8List();
        var out = Uint32List.fromList([
          0xBD334F1D, 0x6E45F25F, 0xF712A214, 0x571FA5CC, //
          0x97410484, 0x6D0AD3AD, 0x7734ECB3, 0xECEE4EEF,
          0xEF7AFD22, 0x70E2E60A, 0xDCE0BA2F, 0xACE6444E,
          0x9A4B41BA, 0x738D6C72, 0xFB166916, 0x03C18E0E,
        ]).buffer.asUint8List();
        var rr = AES(key).convert(inp);
        expect(rr, equals(out));
      });
      test("256-bit CSRC NIST example", () {
        var key = Uint32List.fromList([
          0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781, //
          0x1F352C07, 0x3B6108D7, 0x2D9810A3, 0x0914DFF4,
        ]).buffer.asUint8List();
        var inp = Uint32List.fromList([
          0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A, //
          0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,
          0x30C81C46, 0xA35CE411, 0xE5FBC119, 0x1A0A52EF,
          0xF69F2445, 0xDF4F9B17, 0xAD2B417B, 0xE66C3710
        ]).buffer.asUint8List();
        var out = Uint32List.fromList([
          0xF3EED1BD, 0xB5D2A03C, 0x064B5A7E, 0x3DB181F8, //
          0x591CCB10, 0xD410ED26, 0xDC5BA74A, 0x31362870,
          0xB6ED21B9, 0x9CA6F4F9, 0xF153E7B1, 0xBEAFED1D,
          0x23304B7A, 0x39F9F3FF, 0x067D8D8F, 0x9E24ECC7,
        ]).buffer.asUint8List();
        var rr = AES(key).convert(inp);
        expect(rr, equals(out));
      });
    });
  });
}
