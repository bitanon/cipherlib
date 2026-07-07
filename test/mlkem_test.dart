// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/hashlib.dart' show HashDigest;
import 'package:cipherlib/src/algorithms/mlkem/mlkem_core.dart'
    show
        $polyCompress4,
        $polyCompress5,
        $polyDecompress4,
        $polyDecompress5,
        $polyFromBytes,
        $polyFromMsg,
        $polyToBytes,
        $polyToMsg,
        $rejUniform,
        $vecCompress10,
        $vecCompress11,
        $vecDecompress10,
        $vecDecompress11;
import 'package:test/test.dart';

import 'fixtures/mlkem_decaps_vectors.dart';
import 'fixtures/mlkem_encaps_vectors.dart';
import 'fixtures/mlkem_keygen_vectors.dart';

final kem512 = MLKEM.kem512();
final kem768 = MLKEM.kem768();
final kem1024 = MLKEM.kem1024();
final levels = [kem512, kem768, kem1024];

final keygenVectors = {
  kem512: mlkemKeygen512Vectors,
  kem768: mlkemKeygen768Vectors,
  kem1024: mlkemKeygen1024Vectors,
};
final encapsVectors = {
  kem512: mlkemEncaps512Vectors,
  kem768: mlkemEncaps768Vectors,
  kem1024: mlkemEncaps1024Vectors,
};
final ekCheckVectors = {
  kem512: mlkemEkCheck512Vectors,
  kem768: mlkemEkCheck768Vectors,
  kem1024: mlkemEkCheck1024Vectors,
};
final decapsVectors = {
  kem512: mlkemDecaps512Vectors,
  kem768: mlkemDecaps768Vectors,
  kem1024: mlkemDecaps1024Vectors,
};
final strcmpVectors = {
  kem512: mlkemStrcmp512Vector,
  kem768: mlkemStrcmp768Vector,
  kem1024: mlkemStrcmp1024Vector,
};

void main() {
  group('validation', () {
    test('name', () {
      expect(kem512.name, 'ML-KEM-512');
      expect(kem768.name, 'ML-KEM-768');
      expect(kem1024.name, 'ML-KEM-1024');
    });
    test('parameter sizes', () {
      expect([for (final kem in levels) kem.encapsulationKeySize],
          equals([800, 1184, 1568]));
      expect([for (final kem in levels) kem.decapsulationKeySize],
          equals([1632, 2400, 3168]));
      expect([for (final kem in levels) kem.cipherTextSize],
          equals([768, 1088, 1568]));
      expect([for (final kem in levels) kem.sharedSecretSize],
          equals([32, 32, 32]));
      expect([for (final kem in levels) kem.seedSize], equals([64, 64, 64]));
    });
    test('The seed should be 64 bytes', () {
      for (int i = 0; i < 100; ++i) {
        void cb() => kem512.keygen(seed: Uint8List(i));
        if (i == 64) {
          expect(() => cb(), returnsNormally, reason: 'length: $i');
        } else {
          expect(cb, throwsArgumentError, reason: 'length: $i');
        }
      }
    });
    test('The d and z seeds should be 32 bytes each', () {
      final ok = Uint8List(32);
      expect(() => kem512.$keygen(ok, ok), returnsNormally);
      expect(() => kem512.$keygen(Uint8List(31), ok), throwsArgumentError);
      expect(() => kem512.$keygen(Uint8List(33), ok), throwsArgumentError);
      expect(() => kem512.$keygen(ok, Uint8List(31)), throwsArgumentError);
      expect(() => kem512.$keygen(ok, Uint8List(33)), throwsArgumentError);
    });
    test('The m seed should be 32 bytes', () {
      final ek = kem512.keygen().encapsulationKey;
      expect(() => kem512.$encaps(ek, Uint8List(32)), returnsNormally);
      expect(() => kem512.$encaps(ek, Uint8List(31)), throwsArgumentError);
      expect(() => kem512.$encaps(ek, Uint8List(33)), throwsArgumentError);
    });
    test('encaps rejects wrong encapsulation key lengths', () {
      for (final kem in levels) {
        final n = kem.encapsulationKeySize;
        expect(() => kem.encaps(Uint8List(0)), throwsArgumentError,
            reason: '${kem.name} length: 0');
        expect(() => kem.encaps(Uint8List(n - 1)), throwsArgumentError,
            reason: '${kem.name} length: ${n - 1}');
        expect(() => kem.encaps(Uint8List(n + 1)), throwsArgumentError,
            reason: '${kem.name} length: ${n + 1}');
      }
    });
    test('decaps rejects wrong decapsulation key or cipher text lengths', () {
      for (final kem in levels) {
        final keys = kem.keygen();
        final enc = kem.encaps(keys.encapsulationKey);
        final dk = keys.decapsulationKey;
        final ct = enc.cipherText;
        expect(() => kem.decaps(dk, ct), returnsNormally);
        expect(() => kem.decaps(dk.sublist(1), ct), throwsArgumentError,
            reason: '${kem.name} short dk');
        expect(() => kem.decaps(dk, ct.sublist(1)), throwsArgumentError,
            reason: '${kem.name} short ct');
        expect(() => kem.decaps(ct, dk), throwsArgumentError,
            reason: '${kem.name} swapped arguments');
      }
    });
    test('decaps rejects keys and cipher texts across levels', () {
      final keys = kem768.keygen();
      final enc = kem768.encaps(keys.encapsulationKey);
      expect(() => kem512.decaps(keys.decapsulationKey, enc.cipherText),
          throwsArgumentError);
      expect(() => kem1024.decaps(keys.decapsulationKey, enc.cipherText),
          throwsArgumentError);
      expect(() => kem512.encaps(keys.encapsulationKey), throwsArgumentError);
    });
    test('encaps modulus check (FIPS 203, section 7.2)', () {
      // source: NIST ACVP encapsulationKeyCheck VAL vectors; the failing
      // keys have "noisy linear system values too large". These vectors are
      // all over-length, so they are rejected by the length half of the
      // section 7.2 input check; see the coefficient case below for the
      // modulus half.
      for (final kem in levels) {
        for (final tc in ekCheckVectors[kem]!) {
          final ek = fromHex(tc['ek']!);
          if (tc['passed'] == 'true') {
            expect(() => kem.encaps(ek), returnsNormally,
                reason: '${kem.name} tcId: ${tc['tcId']}');
          } else {
            expect(() => kem.encaps(ek), throwsArgumentError,
                reason: '${kem.name} tcId: ${tc['tcId']}');
          }
        }
      }
    });
    test('encaps rejects a coefficient >= q (FIPS 203, section 7.2)', () {
      // The ACVP encapsulationKeyCheck fail vectors are all over-length, so
      // none exercise the coefficient modulus check on a correctly sized key.
      // Corrupt a valid key so its first 12-bit coefficient is 0xFFF (4095,
      // which is >= q = 3329) to reach that check directly.
      for (final kem in levels) {
        final ek = Uint8List.fromList(kem.keygen().encapsulationKey);
        ek[0] = 0xFF;
        ek[1] = 0xFF; // coeff0 = (0xFF | (0xFF << 8)) & 0xFFF = 0xFFF
        expect(() => kem.encaps(ek), throwsArgumentError, reason: kem.name);
      }
    });
    test('keygen without seed produces random key pairs', () {
      final a = kem512.keygen();
      final b = kem512.keygen();
      expect(a.encapsulationKey, isNot(equals(b.encapsulationKey)));
      expect(a.decapsulationKey, isNot(equals(b.decapsulationKey)));
    });
    test('keygen does not modify the seed buffer', () {
      final seed = Uint8List.fromList(List.filled(64, 7));
      kem768.keygen(seed: seed);
      expect(seed, equals(List.filled(64, 7)));
    });
  });

  group('known inputs', () {
    test('ACVP key generation', () {
      // source: NIST ACVP-Server ML-KEM-keyGen-FIPS203 AFT vectors
      // (see fixtures/mlkem_keygen_vectors.dart)
      for (final kem in levels) {
        for (final tc in keygenVectors[kem]!) {
          final d = fromHex(tc['d']!);
          final z = fromHex(tc['z']!);
          final keys = kem.$keygen(d, z);
          expect(toHex(keys.encapsulationKey), equalsIgnoringCase(tc['ek']!),
              reason: '${kem.name} tcId: ${tc['tcId']} (ek)');
          expect(toHex(keys.decapsulationKey), equalsIgnoringCase(tc['dk']!),
              reason: '${kem.name} tcId: ${tc['tcId']} (dk)');
          // the public API accepts the same vector as seed = d || z
          final seeded = kem.keygen(seed: [...d, ...z]);
          expect(seeded.encapsulationKey, equals(keys.encapsulationKey),
              reason: '${kem.name} tcId: ${tc['tcId']} (seed)');
          expect(seeded.decapsulationKey, equals(keys.decapsulationKey),
              reason: '${kem.name} tcId: ${tc['tcId']} (seed)');
        }
      }
    });
    test('ACVP encapsulation, chained with decapsulation', () {
      // source: NIST ACVP-Server ML-KEM-encapDecap-FIPS203 AFT vectors
      // (see fixtures/mlkem_encaps_vectors.dart)
      for (final kem in levels) {
        for (final tc in encapsVectors[kem]!) {
          final ek = fromHex(tc['ek']!);
          final m = fromHex(tc['m']!);
          final enc = kem.$encaps(ek, m);
          expect(toHex(enc.cipherText), equalsIgnoringCase(tc['c']!),
              reason: '${kem.name} tcId: ${tc['tcId']} (c)');
          expect(enc.sharedSecret.hex(), equalsIgnoringCase(tc['k']!),
              reason: '${kem.name} tcId: ${tc['tcId']} (k)');
          final ss = kem.decaps(fromHex(tc['dk']!), enc.cipherText);
          expect(ss.hex(), equalsIgnoringCase(tc['k']!),
              reason: '${kem.name} tcId: ${tc['tcId']} (decaps)');
        }
      }
    });
    test('ACVP decapsulation, including implicit rejection', () {
      // source: NIST ACVP-Server ML-KEM-encapDecap-FIPS203 VAL vectors;
      // the "modified ciphertext" cases carry the official expected output
      // of the implicit rejection path (see fixtures/mlkem_decaps_vectors.dart)
      for (final kem in levels) {
        for (final tc in decapsVectors[kem]!) {
          final dk = fromHex(tc['dk']!);
          final c = fromHex(tc['c']!);
          final ss = kem.decaps(dk, c);
          expect(ss.hex(), equalsIgnoringCase(tc['k']!),
              reason: '${kem.name} tcId: ${tc['tcId']} (${tc['reason']})');
        }
      }
    });
    test('CCTV strcmp decapsulation', () {
      // source: C2SP/CCTV strcmp vectors; the re-encrypted ciphertext
      // comparison contains early zero bytes
      // (see fixtures/mlkem_decaps_vectors.dart)
      for (final kem in levels) {
        final tc = strcmpVectors[kem]!;
        final ss = kem.decaps(fromHex(tc['dk']!), fromHex(tc['c']!));
        expect(ss.hex(), equalsIgnoringCase(tc['k']!), reason: kem.name);
      }
    });
  });

  group('serialization', () {
    // Circular (mod q) distance between two coefficients.
    int cdist(int a, int b) {
      final d = ((a - b) % 3329 + 3329) % 3329;
      return d < 3329 - d ? d : 3329 - d;
    }

    // Sweeps every residue 0..q-1 through a 256-coefficient pack/unpack round
    // trip and checks the FIPS 203 (Section 4.2.1) compression error bound:
    // Decompress(Compress_d(x)) differs from x by at most ceil(q / 2^(d+1)).
    // A [bound] of 0 means the transform must be lossless. Exercises the
    // compress/decompress twins (arith_64bit / arith_32bit) directly, so it
    // runs on both the VM and node.
    void sweep(
      int byteLength,
      void Function(Int16List orig, Uint8List bytes) pack,
      void Function(Uint8List bytes, Int16List out) unpack,
      int bound,
    ) {
      final orig = Int16List(256);
      final out = Int16List(256);
      final bytes = Uint8List(byteLength);
      var maxErr = 0;
      for (var base = 0; base < 3329; base += 256) {
        for (var i = 0; i < 256; ++i) {
          orig[i] = (base + i) % 3329;
        }
        pack(orig, bytes);
        unpack(bytes, out);
        for (var i = 0; i < 256; ++i) {
          final e = cdist(orig[i], out[i]);
          if (e > maxErr) maxErr = e;
          expect(e, lessThanOrEqualTo(bound),
              reason: 'x=${orig[i]} -> ${out[i]}');
        }
      }
      // Guard against a transform that is trivially lossless (a broken
      // compressor acting as identity): a lossy variant must actually lose
      // precision and reach its bound.
      if (bound == 0) {
        expect(maxErr, 0);
      } else {
        expect(maxErr, inInclusiveRange(1, bound));
      }
    }

    test('ByteEncode12/ByteDecode12 is lossless over 0..q-1', () {
      sweep(384, (o, b) => $polyToBytes(b, 0, o, 0),
          (b, out) => $polyFromBytes(out, 0, b, 0), 0);
    });
    test('Compress/Decompress d=4 within the error bound', () {
      // ceil(3329 / 2^5) = 105
      sweep(128, (o, b) => $polyCompress4(b, 0, o, 0),
          (b, out) => $polyDecompress4(out, 0, b, 0), 105);
    });
    test('Compress/Decompress d=5 within the error bound', () {
      // ceil(3329 / 2^6) = 53
      sweep(160, (o, b) => $polyCompress5(b, 0, o, 0),
          (b, out) => $polyDecompress5(out, 0, b, 0), 53);
    });
    test('Compress/Decompress d=10 within the error bound', () {
      // ceil(3329 / 2^11) = 2
      sweep(320, (o, b) => $vecCompress10(b, 0, o, 1),
          (b, out) => $vecDecompress10(out, b, 0, 1), 2);
    });
    test('Compress/Decompress d=11 within the error bound', () {
      // ceil(3329 / 2^12) = 1
      sweep(352, (o, b) => $vecCompress11(b, 0, o, 1),
          (b, out) => $vecDecompress11(out, b, 0, 1), 1);
    });
    test('poly message encode/decode round trip', () {
      // FIPS 203 Compress_1 / Decompress_1: a bit maps to 0 or 1665 and back.
      final poly = Int16List(256);
      final out = Uint8List(32);
      for (final msg in <List<int>>[
        List.filled(32, 0),
        List.filled(32, 0xFF),
        List.generate(32, (i) => (i * 37) & 0xFF),
        List.generate(32, (i) => (i * i * 91 + 13) & 0xFF),
      ]) {
        final m = Uint8List.fromList(msg);
        $polyFromMsg(poly, 0, m, 0);
        $polyToMsg(out, 0, poly, 0);
        expect(out, equals(m), reason: toHex(m));
      }
    });
  });

  group('correctness', () {
    test('rejection sampling continues across any number of XOF blocks', () {
      // SampleNTT needs more than the usual 3 XOF blocks with probability
      // ~2^-38 per call (see C2SP/CCTV), which no fixed vector for the final
      // FIPS 203 exists for; this exercises the block continuation directly.
      final r = Int16List(256);
      final junk = Uint8List(168); // 0xFF bytes encode 4095 >= q: rejected
      junk.fillRange(0, 168, 0xFF);
      final good = Uint8List(168); // zero bytes encode 0 < q: accepted
      int ctr = 0;
      for (int block = 0; block < 5; block++) {
        ctr = $rejUniform(r, 0, ctr, junk, 168);
        expect(ctr, 0, reason: '[block: $block]');
      }
      ctr = $rejUniform(r, 0, ctr, good, 168);
      expect(ctr, 112); // 2 coefficients per 3 bytes
      ctr = $rejUniform(r, 0, ctr, good, 168);
      expect(ctr, 224);
      ctr = $rejUniform(r, 0, ctr, good, 168);
      expect(ctr, 256); // stops at 256 even with input to spare
    });
    test('keygen -> encaps -> decaps round trip', () {
      for (final kem in levels) {
        for (int j = 0; j < 10; ++j) {
          final keys = kem.keygen();
          final enc = kem.encaps(keys.encapsulationKey);
          final ss = kem.decaps(keys.decapsulationKey, enc.cipherText);
          expect(ss.isEqual(enc.sharedSecret), isTrue,
              reason: '${kem.name} [iter: $j]');
        }
      }
    });
    test('same seed produces identical key pairs', () {
      for (final kem in levels) {
        final seed = List.generate(64, (i) => i);
        final a = kem.keygen(seed: seed);
        final b = kem.keygen(seed: seed);
        expect(a.encapsulationKey, equals(b.encapsulationKey),
            reason: kem.name);
        expect(a.decapsulationKey, equals(b.decapsulationKey),
            reason: kem.name);
      }
    });
    test('same (ek, m) produces identical encapsulation', () {
      final keys = kem768.keygen();
      final m = List.generate(32, (i) => 32 - i);
      final a = kem768.$encaps(keys.encapsulationKey, m);
      final b = kem768.$encaps(keys.encapsulationKey, m);
      expect(a.cipherText, equals(b.cipherText));
      expect(a.sharedSecret.isEqual(b.sharedSecret), isTrue);
    });
    test('random encapsulations produce different secrets', () {
      final keys = kem768.keygen();
      final a = kem768.encaps(keys.encapsulationKey);
      final b = kem768.encaps(keys.encapsulationKey);
      expect(a.cipherText, isNot(equals(b.cipherText)));
      expect(a.sharedSecret.isEqual(b.sharedSecret), isFalse);
    });
    test('tampered cipher text is implicitly rejected', () {
      for (final kem in levels) {
        final keys = kem.keygen();
        final enc = kem.encaps(keys.encapsulationKey);
        for (final at in [0, kem.cipherTextSize >> 1, kem.cipherTextSize - 1]) {
          final bad = Uint8List.fromList(enc.cipherText);
          bad[at] ^= 0xFF;
          late HashDigest ss;
          expect(() => ss = kem.decaps(keys.decapsulationKey, bad),
              returnsNormally,
              reason: '${kem.name} [byte: $at]');
          expect(ss.isEqual(enc.sharedSecret), isFalse,
              reason: '${kem.name} [byte: $at]');
        }
      }
    });
    test('decapsulation with a different key of the same level', () {
      final alice = kem512.keygen();
      final mallory = kem512.keygen();
      final enc = kem512.encaps(alice.encapsulationKey);
      late HashDigest ss;
      expect(() => ss = kem512.decaps(mallory.decapsulationKey, enc.cipherText),
          returnsNormally);
      expect(ss.isEqual(enc.sharedSecret), isFalse);
    });
  });
}
