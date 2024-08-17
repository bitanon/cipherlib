// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

@Tags(['vm-only'])

import 'dart:typed_data' show Uint8List;

import 'package:cipherlib/cipherlib.dart' as my;
import 'package:cipherlib/src/cipherlib_base.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:hashlib_codecs/hashlib_codecs.dart';
import 'package:pointycastle/pointycastle.dart' as pc;
import 'package:test/test.dart';

import 'utils.dart';

void main() {
  group('ChaCha20', () {
    test('pointycastle: ChaCha20/20', () {
      var key = randomBytes(32);
      var nonce = randomBytes(8);
      for (int j = 0; j < 100; ++j) {
        var text = randomBytes(j);
        var result = my.chacha20(
          text,
          key,
          nonce: nonce,
          counter: Nonce64.zero(),
        );
        var instance = pc.StreamCipher('ChaCha20/20');
        instance.init(
          true,
          pc.ParametersWithIV(pc.KeyParameter(key), nonce),
        );
        var out = instance.process(text);
        expect(out, equals(result), reason: '[text: $j]');
      }
    });
    test('pointycastle: ChaCha7539/20', () {
      var key = randomBytes(32);
      var nonce = randomBytes(12);
      for (int j = 0; j < 100; ++j) {
        var text = randomBytes(j);
        var result = my.chacha20(
          text,
          key,
          nonce: nonce,
          counter: Nonce64.zero(),
        );
        var instance = pc.StreamCipher('ChaCha7539/20');
        instance.init(
          true,
          pc.ParametersWithIV(pc.KeyParameter(key), nonce),
        );
        var out = instance.process(text);
        expect(out, equals(result), reason: '[text: $j]');
      }
    });
    test('pointycastle: ChaCha20/20: 16-byte key', () {
      var key = randomBytes(16);
      var nonce = randomBytes(8);
      for (int j = 0; j < 100; ++j) {
        var text = randomBytes(j);
        var result = my.chacha20(
          text,
          key,
          nonce: nonce,
          counter: Nonce64.zero(),
        );
        var instance = pc.StreamCipher('ChaCha20/20');
        instance.init(
          true,
          pc.ParametersWithIV(pc.KeyParameter(key), nonce),
        );
        var out = instance.process(text);
        expect(out, equals(result), reason: '[text: $j]');
      }
    });
  });

  group('ChaCha20/Poly1305', () {
    test('cryptography: encryption + tag', () async {
      var key = randomBytes(32);
      for (int j = 0; j < 300; ++j) {
        var nonce = randomBytes(12);
        var text = randomBytes(j);
        var aad = randomBytes(key[0]);
        var result = my.chacha20poly1305(
          text,
          key,
          nonce: nonce,
          aad: aad,
        );
        var out = await crypto.Chacha20.poly1305Aead().encrypt(
          text,
          secretKey: crypto.SecretKey(key),
          nonce: nonce,
          aad: aad,
        );
        expect(out.cipherText, equals(result.data),
            reason: '[text: $j, aad: ${key[0]}]');
        expect(out.mac.bytes, equals(result.tag.bytes),
            reason: '[text: $j, aad: ${key[0]}]]');
      }
    });
  });

  group('Salsa20', () {
    test('pointycastle', () {
      var key = randomBytes(32);
      var nonce = randomBytes(8);
      for (int j = 0; j < 100; ++j) {
        var text = randomBytes(j);
        var result = my.salsa20(text, key, nonce: nonce);
        var instance = pc.StreamCipher('Salsa20');
        instance.init(
          true,
          pc.ParametersWithIV(pc.KeyParameter(key), nonce),
        );
        var out = instance.process(text);
        expect(out, equals(result), reason: '[text: $j]');
      }
    });
  });

  group('AES/ECB', () {
    test('pointycastle: encryption with 128-bit key', () {
      var key = randomBytes(16);
      for (int j = 16; j < 300; j += 16) {
        var text = randomBytes(j);
        var result = my.AES.noPadding(key).ecb().encrypt(text);
        var instance = pc.BlockCipher('AES/ECB');
        instance.init(true, pc.KeyParameter(key));
        var out = Uint8List(j);
        for (int i = 0; i < j; i += 16) {
          instance.processBlock(text, i, out, i);
        }
        expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
      }
    });
    test('pointycastle: encryption with 192-bit key', () {
      var key = randomBytes(24);
      for (int j = 16; j < 300; j += 16) {
        var text = randomBytes(j);
        var result = my.AES.noPadding(key).ecb().encrypt(text);
        var instance = pc.BlockCipher('AES/ECB');
        instance.init(true, pc.KeyParameter(key));
        var out = Uint8List(j);
        for (int i = 0; i < j; i += 16) {
          instance.processBlock(text, i, out, i);
        }
        expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
      }
    });
    test('pointycastle: encryption with 256-bit key', () {
      var key = randomBytes(32);
      for (int j = 16; j < 300; j += 16) {
        var text = randomBytes(j);
        var result = my.AES.noPadding(key).ecb().encrypt(text);
        var instance = pc.BlockCipher('AES/ECB');
        instance.init(true, pc.KeyParameter(key));
        var out = Uint8List(j);
        for (int i = 0; i < j; i += 16) {
          instance.processBlock(text, i, out, i);
        }
        expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
      }
    });
  });

  group('AES/CBC', () {
    test('pointycastle: encryption with 128-bit key', () {
      var key = randomBytes(16);
      for (int j = 16; j < 300; j += 16) {
        var text = randomBytes(j);
        var iv = randomBytes(16);
        var result = my.AES.noPadding(key).cbc(iv).encrypt(text);
        var instance = pc.BlockCipher('AES/CBC');
        instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
        var out = Uint8List(j);
        for (int i = 0; i < j; i += 16) {
          instance.processBlock(text, i, out, i);
        }
        expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
      }
    });
    test('pointycastle: encryption with 192-bit key', () {
      var key = randomBytes(24);
      for (int j = 16; j < 300; j += 16) {
        var text = randomBytes(j);
        var iv = randomBytes(16);
        var result = my.AES.noPadding(key).cbc(iv).encrypt(text);
        var instance = pc.BlockCipher('AES/CBC');
        instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
        var out = Uint8List(j);
        for (int i = 0; i < j; i += 16) {
          instance.processBlock(text, i, out, i);
        }
        expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
      }
    });
    test('pointycastle: encryption with 256-bit key', () {
      var key = randomBytes(32);
      for (int j = 16; j < 300; j += 16) {
        var text = randomBytes(j);
        var iv = randomBytes(16);
        var result = my.AES.noPadding(key).cbc(iv).encrypt(text);
        var instance = pc.BlockCipher('AES/CBC');
        instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
        var out = Uint8List(j);
        for (int i = 0; i < j; i += 16) {
          instance.processBlock(text, i, out, i);
        }
        expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
      }
    });
  });

  group('AES/IGE', () {
    test('pointycastle: encryption with 128-bit key', () {
      var key = randomBytes(16);
      for (int j = 16; j < 300; j += 16) {
        var text = randomBytes(j);
        var iv = randomBytes(32);
        var result = my.AES.noPadding(key).ige(iv).encrypt(text);
        var instance = pc.BlockCipher('AES/IGE');
        instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
        var out = Uint8List(j);
        for (int i = 0; i < j; i += 16) {
          instance.processBlock(text, i, out, i);
        }
        expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
      }
    });
    test('pointycastle: encryption with 192-bit key', () {
      var key = randomBytes(24);
      for (int j = 16; j < 300; j += 16) {
        var text = randomBytes(j);
        var iv = randomBytes(32);
        var result = my.AES.noPadding(key).ige(iv).encrypt(text);
        var instance = pc.BlockCipher('AES/IGE');
        instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
        var out = Uint8List(j);
        for (int i = 0; i < j; i += 16) {
          instance.processBlock(text, i, out, i);
        }
        expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
      }
    });
    test('pointycastle: encryption with 256-bit key', () {
      var key = randomBytes(32);
      for (int j = 16; j < 300; j += 16) {
        var text = randomBytes(j);
        var iv = randomBytes(32);
        var result = my.AES.noPadding(key).ige(iv).encrypt(text);
        var instance = pc.BlockCipher('AES/IGE');
        instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
        var out = Uint8List(j);
        for (int i = 0; i < j; i += 16) {
          instance.processBlock(text, i, out, i);
        }
        expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
      }
    });
  });

  group('AES/CFB-64', () {
    test('pointycastle: encryption with 128-bit key', () {
      var key = randomBytes(16);
      for (int j = 16; j < 300; j += 16) {
        var text = randomBytes(j);
        var iv = randomBytes(16);
        var result = my.AES.noPadding(key).cfb64(iv).encrypt(text);
        var instance = pc.BlockCipher('AES/CFB-64');
        instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
        var out = Uint8List(j);
        for (int i = 0; i < j; i += 8) {
          instance.processBlock(text, i, out, i);
        }
        expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
      }
    });
    test('pointycastle: encryption with 192-bit key', () {
      var key = randomBytes(24);
      for (int j = 16; j < 300; j += 16) {
        var text = randomBytes(j);
        var iv = randomBytes(16);
        var result = my.AES.noPadding(key).cfb64(iv).encrypt(text);
        var instance = pc.BlockCipher('AES/CFB-64');
        instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
        var out = Uint8List(j);
        for (int i = 0; i < j; i += 8) {
          instance.processBlock(text, i, out, i);
        }
        expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
      }
    });
    test('pointycastle: encryption with 256-bit key', () {
      var key = randomBytes(32);
      for (int j = 16; j < 300; j += 16) {
        var text = randomBytes(j);
        var iv = randomBytes(16);
        var result = my.AES.noPadding(key).cfb64(iv).encrypt(text);
        var instance = pc.BlockCipher('AES/CFB-64');
        instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
        var out = Uint8List(j);
        for (int i = 0; i < j; i += 8) {
          instance.processBlock(text, i, out, i);
        }
        expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
      }
    });

    group('AES/OFB-64', () {
      test('pointycastle: encryption with 128-bit key', () {
        var key = randomBytes(16);
        for (int j = 16; j < 300; j += 16) {
          var text = randomBytes(j);
          var iv = randomBytes(16);
          var result = my.AES.noPadding(key).ofb64(iv).encrypt(text);
          var instance = pc.BlockCipher('AES/OFB-64');
          instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
          var out = Uint8List(j);
          for (int i = 0; i < j; i += 8) {
            instance.processBlock(text, i, out, i);
          }
          expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
        }
      });
      test('pointycastle: encryption with 192-bit key', () {
        var key = randomBytes(24);
        for (int j = 16; j < 300; j += 16) {
          var text = randomBytes(j);
          var iv = randomBytes(16);
          var result = my.AES.noPadding(key).ofb64(iv).encrypt(text);
          var instance = pc.BlockCipher('AES/OFB-64');
          instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
          var out = Uint8List(j);
          for (int i = 0; i < j; i += 8) {
            instance.processBlock(text, i, out, i);
          }
          expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
        }
      });
      test('pointycastle: encryption with 256-bit key', () {
        var key = randomBytes(32);
        for (int j = 16; j < 300; j += 16) {
          var text = randomBytes(j);
          var iv = randomBytes(16);
          var result = my.AES.noPadding(key).ofb64(iv).encrypt(text);
          var instance = pc.BlockCipher('AES/OFB-64');
          instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
          var out = Uint8List(j);
          for (int i = 0; i < j; i += 8) {
            instance.processBlock(text, i, out, i);
          }
          expect(toHex(out), equals(toHex(result)), reason: '[size: $j]');
        }
      });
    });
  });
}
