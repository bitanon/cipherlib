// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/aes/_core.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

void main() {
  test('throws error on invalid key size', () {
    expect(() => AESCore.$expandEncryptionKey(Uint32List(0)), throwsStateError);
  });
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
}
