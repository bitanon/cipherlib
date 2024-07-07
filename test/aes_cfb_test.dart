// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/hashlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:test/test.dart';

void main() {
  group('NIST SP 800-38A', () {
    // https://csrc.nist.gov/pubs/sp/800/38/a/final
    // https://www.ibm.com/docs/en/linux-on-systems?topic=examples-aes-cfb-mode-example
    group('CFB data - 1 for AES128', () {
      var key = Uint8List.fromList([
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, //
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
      ]);
      var iv = Uint8List.fromList([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]);
      var data = Uint8List.fromList([
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, //
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
      ]);
      var expected = Uint8List.fromList([
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, //
        0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
      ]);
      test('encrypt', () {
        var actual = AES(key).cfb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decrypt', () {
        var reverse = AES(key).cfb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('CFB data - 2 for AES128', () {
      var key = Uint8List.fromList([
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, //
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
      ]);
      var iv = Uint8List.fromList([
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, //
        0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
      ]);
      var data = Uint8List.fromList([
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, //
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
      ]);
      var expected = Uint8List.fromList([
        0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f, //
        0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b,
      ]);
      test('encrypt', () {
        var actual = AES(key).cfb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decrypt', () {
        var reverse = AES(key).cfb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('CFB data - 3 for AES128', () {
      var key = Uint8List.fromList([
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, //
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
      ]);
      var iv = Uint8List.fromList([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]);
      var data = Uint8List.fromList([
        0x6b,
      ]);
      var expected = Uint8List.fromList([
        0x3b,
      ]);
      test('encrypt', () {
        var actual = AES(key).cfb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decrypt', () {
        var reverse = AES(key).cfb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('CFB data - 4 for AES128', () {
      var key = Uint8List.fromList([
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, //
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
      ]);
      var iv = Uint8List.fromList([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x3b,
      ]);
      var data = Uint8List.fromList([
        0xc1,
      ]);
      var expected = Uint8List.fromList([
        0x79,
      ]);
      test('encrypt', () {
        var actual = AES(key).cfb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decrypt', () {
        var reverse = AES(key).cfb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('CFB data - 5 for AES192', () {
      var key = Uint8List.fromList([
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, //
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
      ]);
      var iv = Uint8List.fromList([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]);
      var data = Uint8List.fromList([
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, //
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
      ]);
      var expected = Uint8List.fromList([
        0xcd, 0xc8, 0x0d, 0x6f, 0xdd, 0xf1, 0x8c, 0xab, //
        0x34, 0xc2, 0x59, 0x09, 0xc9, 0x9a, 0x41, 0x74,
      ]);
      test('encrypt', () {
        var actual = AES(key).cfb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decrypt', () {
        var reverse = AES(key).cfb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('CFB data - 6 for AES192', () {
      var key = Uint8List.fromList([
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, //
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
      ]);
      var iv = Uint8List.fromList([
        0xcd, 0xc8, 0x0d, 0x6f, 0xdd, 0xf1, 0x8c, 0xab, //
        0x34, 0xc2, 0x59, 0x09, 0xc9, 0x9a, 0x41, 0x74,
      ]);
      var data = Uint8List.fromList([
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, //
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
      ]);
      var expected = Uint8List.fromList([
        0x67, 0xce, 0x7f, 0x7f, 0x81, 0x17, 0x36, 0x21, //
        0x96, 0x1a, 0x2b, 0x70, 0x17, 0x1d, 0x3d, 0x7a,
      ]);
      test('encrypt', () {
        var actual = AES(key).cfb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decrypt', () {
        var reverse = AES(key).cfb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('CFB data - 7 for AES192', () {
      var key = Uint8List.fromList([
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, //
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
      ]);
      var iv = Uint8List.fromList([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]);
      var data = Uint8List.fromList([
        0x6b,
      ]);
      var expected = Uint8List.fromList([
        0xcd,
      ]);
      test('encrypt', () {
        var actual = AES(key).cfb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decrypt', () {
        var reverse = AES(key).cfb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('CFB data - 8 for AES192', () {
      var key = Uint8List.fromList([
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, //
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
      ]);
      var iv = Uint8List.fromList([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xcd,
      ]);
      var data = Uint8List.fromList([
        0xc1,
      ]);
      var expected = Uint8List.fromList([
        0xa2,
      ]);
      test('encrypt', () {
        var actual = AES(key).cfb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decrypt', () {
        var reverse = AES(key).cfb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('CFB data - 9 for AES256', () {
      var key = Uint8List.fromList([
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, //
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
      ]);
      var iv = Uint8List.fromList([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]);
      var data = Uint8List.fromList([
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, //
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
      ]);
      var expected = Uint8List.fromList([
        0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b, //
        0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
      ]);
      test('encrypt', () {
        var actual = AES(key).cfb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decrypt', () {
        var reverse = AES(key).cfb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('CFB data - 10 for AES256', () {
      var key = Uint8List.fromList([
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, //
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
      ]);
      var iv = Uint8List.fromList([
        0xdc, 0x7e, 0x84, 0xbf, 0xda, 0x79, 0x16, 0x4b, //
        0x7e, 0xcd, 0x84, 0x86, 0x98, 0x5d, 0x38, 0x60,
      ]);
      var data = Uint8List.fromList([
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, //
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
      ]);
      var expected = Uint8List.fromList([
        0x39, 0xff, 0xed, 0x14, 0x3b, 0x28, 0xb1, 0xc8, //
        0x32, 0x11, 0x3c, 0x63, 0x31, 0xe5, 0x40, 0x7b,
      ]);
      test('encrypt', () {
        var actual = AES(key).cfb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decrypt', () {
        var reverse = AES(key).cfb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('CFB data - 11 for AES256', () {
      var key = Uint8List.fromList([
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, //
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
      ]);
      var iv = Uint8List.fromList([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]);
      var data = Uint8List.fromList([
        0x6b,
      ]);
      var expected = Uint8List.fromList([
        0xdc,
      ]);
      test('encrypt', () {
        var actual = AES(key).cfb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decrypt', () {
        var reverse = AES(key).cfb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
    group('CFB data - 11 for AES256', () {
      var key = Uint8List.fromList([
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, //
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
      ]);
      var iv = Uint8List.fromList([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xdc,
      ]);
      var data = Uint8List.fromList([
        0xc1,
      ]);
      var expected = Uint8List.fromList([
        0x1f,
      ]);
      test('encrypt', () {
        var actual = AES(key).cfb(iv).encrypt(data);
        expect(toHex(actual), equals(toHex(expected)));
      });
      test('decrypt', () {
        var reverse = AES(key).cfb(iv).decrypt(expected);
        expect(toHex(reverse), equals(toHex(data)));
      });
    });
  });

  test('throws error on invalid salt size', () {
    var aes = AES(Uint8List(16));
    expect(() => aes.cfb(Uint8List(15)).encrypt([0]), throwsStateError);
    expect(() => aes.cfb(Uint8List(8)).decrypt([0]), throwsStateError);
  });

  group("Zero IV", () {
    group('AES128', () {
      var key = 'abcdefghijklmnop'.codeUnits;
      var iv = Uint8List(16);
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromBase64('tEUQSPkqjLK6MZkW7O9DujeXuxsUiJtfyA==');
      var aes = AES.pkcs7(key).cfb(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('AES192', () {
      var key = 'abcdefghijklmnopqrstuvwx'.codeUnits;
      var iv = Uint8List(16);
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromBase64('umoiqsbvbhRFB+FVYdGjuwfCo5rQFz/uQw==');
      var aes = AES.pkcs7(key).cfb(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('AES256', () {
      var key = 'abcdefghijklmnopqrstuvwxyz012345'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var iv = Uint8List(16);
      var cipher = fromBase64('gQOajlfwdgmrSB/mIVYUl1zCxL6F050zRw==');
      var aes = AES.pkcs7(key).cfb(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
  });

  group('encryption <-> decryption', () {
    test("AES128/CFB", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).cfb(iv).encrypt(inp);
        var plain = AES(key).cfb(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES192/CFB", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).cfb(iv).encrypt(inp);
        var plain = AES(key).cfb(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("AES256/CFB", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).cfb(iv).encrypt(inp);
        var plain = AES(key).cfb(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
  });

  group('sink test', () {
    test('encryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = randomBytes(16);
        final aes = AES(key).cfb(iv);

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
        var iv = randomBytes(16);
        final aes = AES(key).cfb(iv);

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

  test('reset iv', () {
    var iv = randomBytes(16);
    var key = randomBytes(24);
    var aes = AES(key).cfb(iv);
    for (int j = 0; j < 100; j++) {
      aes.resetIV();
      var inp = randomBytes(j);
      var cipher = aes.encrypt(inp);
      var plain = aes.decrypt(cipher);
      expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
    }
  });
}
