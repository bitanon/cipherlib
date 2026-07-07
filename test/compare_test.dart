// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: library_annotations

@Tags(['vm-only'])

import 'dart:typed_data' show Uint8List;

import 'package:cipherlib/cipherlib.dart' as my;
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/src/utils/nonce.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:hashlib/random.dart';
import 'package:pointycastle/pointycastle.dart' as pc;
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/blowfish.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/block/modes/ccm.dart';
import 'package:pointycastle/block/modes/ecb.dart';
import 'package:pointycastle/block/twofish.dart';
import 'package:pointycastle/stream/ctr.dart';
import 'package:test/test.dart';

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
        expect(out.mac.bytes, equals(result.mac.bytes),
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
        expect(toHex(out), equals(toHex(result)), reason: '[text: $j]');
      }
    });
  });

  group('AES/CCM', () {
    test('pointycastle: encryption with 128-bit key', () {
      final key = randomBytes(16);
      for (int j = 0; j < 200; ++j) {
        final nonce = randomBytes(13);
        final aad = randomBytes((j * 3) % 40);
        final text = randomBytes(j);
        final result =
            my.AES(key).ccm(nonce, aad: aad, tagSize: 8).encrypt(text);

        final encrypter = CCMBlockCipher(AESEngine())
          ..init(
            true,
            pc.AEADParameters(pc.KeyParameter(key), 64, nonce, aad),
          );
        final out = encrypter.process(Uint8List.fromList(text));
        expect(out, equals(result), reason: '[size: $j]');

        final decrypter = CCMBlockCipher(AESEngine())
          ..init(
            false,
            pc.AEADParameters(pc.KeyParameter(key), 64, nonce, aad),
          );
        expect(decrypter.process(Uint8List.fromList(result)), equals(text),
            reason: '[size: $j]');
      }
    });

    test('pointycastle: encryption with large aad', () {
      final key = randomBytes(16);
      final nonce = randomBytes(13);
      final text = randomBytes(32);
      // AAD of 0xFF00 bytes and above uses the extended length encoding
      for (final n in [0xFEFF, 0xFF00, 0x10000]) {
        final aad = randomBytes(n);
        final result =
            my.AES(key).ccm(nonce, aad: aad, tagSize: 16).encrypt(text);
        final encrypter = CCMBlockCipher(AESEngine())
          ..init(
            true,
            pc.AEADParameters(pc.KeyParameter(key), 128, nonce, aad),
          );
        final out = encrypter.process(Uint8List.fromList(text));
        expect(out, equals(result), reason: '[aad: $n]');
      }
    });

    test('pointycastle: encryption with 192-bit key', () {
      final key = randomBytes(24);
      for (int j = 0; j < 200; ++j) {
        final nonce = randomBytes(13);
        final aad = randomBytes((j * 5) % 40);
        final text = randomBytes(j);
        final result =
            my.AES(key).ccm(nonce, aad: aad, tagSize: 10).encrypt(text);

        final encrypter = CCMBlockCipher(AESEngine())
          ..init(
            true,
            pc.AEADParameters(pc.KeyParameter(key), 80, nonce, aad),
          );
        final out = encrypter.process(Uint8List.fromList(text));
        expect(out, equals(result), reason: '[size: $j]');

        final decrypter = CCMBlockCipher(AESEngine())
          ..init(
            false,
            pc.AEADParameters(pc.KeyParameter(key), 80, nonce, aad),
          );
        expect(decrypter.process(Uint8List.fromList(result)), equals(text),
            reason: '[size: $j]');
      }
    });

    test('pointycastle: encryption with 256-bit key', () {
      final key = randomBytes(32);
      for (int j = 0; j < 200; ++j) {
        final nonce = randomBytes(13);
        final aad = randomBytes((j * 7) % 40);
        final text = randomBytes(j);
        final result =
            my.AES(key).ccm(nonce, aad: aad, tagSize: 16).encrypt(text);

        final encrypter = CCMBlockCipher(AESEngine())
          ..init(
            true,
            pc.AEADParameters(pc.KeyParameter(key), 128, nonce, aad),
          );
        final out = encrypter.process(Uint8List.fromList(text));
        expect(out, equals(result), reason: '[size: $j]');

        final decrypter = CCMBlockCipher(AESEngine())
          ..init(
            false,
            pc.AEADParameters(pc.KeyParameter(key), 128, nonce, aad),
          );
        expect(decrypter.process(Uint8List.fromList(result)), equals(text),
            reason: '[size: $j]');
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

  group('Blowfish', () {
    test('pointycastle: ECB encryption', () {
      // pointycastle only supports keys of 4 to 56 bytes
      for (int k = 4; k <= 56; k += 4) {
        var key = randomBytes(k);
        for (int j = 8; j < 200; j += 8) {
          var text = randomBytes(j);
          var result = my.Blowfish.noPadding(key).ecb().encrypt(text);
          var instance = ECBBlockCipher(BlowfishEngine());
          instance.init(true, pc.KeyParameter(key));
          var out = Uint8List(j);
          for (int i = 0; i < j; i += 8) {
            instance.processBlock(text, i, out, i);
          }
          expect(toHex(out), equals(toHex(result)),
              reason: '[key: $k, size: $j]');
        }
      }
    });
    test('pointycastle: CBC encryption', () {
      // pointycastle only supports keys of 4 to 56 bytes
      for (int k = 4; k <= 56; k += 4) {
        var key = randomBytes(k);
        for (int j = 8; j < 200; j += 8) {
          var text = randomBytes(j);
          var iv = randomBytes(8);
          var result = my.Blowfish.noPadding(key).cbc(iv).encrypt(text);
          var instance = CBCBlockCipher(BlowfishEngine());
          instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
          var out = Uint8List(j);
          for (int i = 0; i < j; i += 8) {
            instance.processBlock(text, i, out, i);
          }
          expect(toHex(out), equals(toHex(result)),
              reason: '[key: $k, size: $j]');
        }
      }
    });
    test('pointycastle: CTR encryption', () {
      // pointycastle only supports keys of 4 to 56 bytes
      for (int k = 4; k <= 56; k += 4) {
        var key = randomBytes(k);
        for (int j = 0; j < 200; ++j) {
          var text = randomBytes(j);
          var iv = randomBytes(8);
          var result = my.Blowfish(key).ctr(iv).encrypt(text);
          var instance = CTRStreamCipher(BlowfishEngine());
          instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
          var out = instance.process(text);
          expect(toHex(out), equals(toHex(result)),
              reason: '[key: $k, size: $j]');
        }
      }
    });
  });

  group('Twofish', () {
    test('pointycastle: ECB encryption', () {
      for (int k in [16, 24, 32]) {
        var key = randomBytes(k);
        for (int j = 16; j < 300; j += 16) {
          var text = randomBytes(j);
          var result = my.Twofish.noPadding(key).ecb().encrypt(text);
          var instance = ECBBlockCipher(TwofishEngine());
          instance.init(true, pc.KeyParameter(key));
          var out = Uint8List(j);
          for (int i = 0; i < j; i += 16) {
            instance.processBlock(text, i, out, i);
          }
          expect(toHex(out), equals(toHex(result)),
              reason: '[key: $k, size: $j]');
        }
      }
    });
    test('pointycastle: CBC encryption', () {
      for (int k in [16, 24, 32]) {
        var key = randomBytes(k);
        for (int j = 16; j < 300; j += 16) {
          var text = randomBytes(j);
          var iv = randomBytes(16);
          var result = my.Twofish.noPadding(key).cbc(iv).encrypt(text);
          var instance = CBCBlockCipher(TwofishEngine());
          instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
          var out = Uint8List(j);
          for (int i = 0; i < j; i += 16) {
            instance.processBlock(text, i, out, i);
          }
          expect(toHex(out), equals(toHex(result)),
              reason: '[key: $k, size: $j]');
        }
      }
    });
    test('pointycastle: CTR encryption', () {
      for (int k in [16, 24, 32]) {
        var key = randomBytes(k);
        for (int j = 0; j < 200; ++j) {
          var text = randomBytes(j);
          var iv = randomBytes(16);
          var result = my.Twofish(key).ctr(iv, 128).encrypt(text);
          var instance = CTRStreamCipher(TwofishEngine());
          instance.init(true, pc.ParametersWithIV(pc.KeyParameter(key), iv));
          var out = instance.process(text);
          expect(toHex(out), equals(toHex(result)),
              reason: '[key: $k, size: $j]');
        }
      }
    });
  });
}
