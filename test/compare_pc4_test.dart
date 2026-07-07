// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: library_annotations

// The Blowfish and Twofish engines only exist in pointycastle >= 4.0.0, which
// requires Dart SDK 3.2+. On the 2.19 floor pub resolves an older pointycastle
// without these libraries, so this file cannot compile there. The generic
// `stable-only` tag lets CI exclude it (`-x stable-only`) on non-stable SDKs,
// where the file is skipped at the parse phase before it is ever compiled.
@Tags(['vm-only', 'stable-only'])

import 'dart:typed_data' show Uint8List;

import 'package:cipherlib/cipherlib.dart' as my;
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';
import 'package:pointycastle/pointycastle.dart' as pc;
import 'package:pointycastle/block/blowfish.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/block/modes/ecb.dart';
import 'package:pointycastle/block/twofish.dart';
import 'package:pointycastle/stream/ctr.dart';
import 'package:test/test.dart';

void main() {
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
