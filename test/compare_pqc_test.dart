// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: library_annotations

// Every pqcrypto version requires Dart SDK 3.10+, so on the 2.19 floor pub
// cannot resolve `pqcrypto: any` and this file cannot compile. The generic
// `stable-only` tag lets CI exclude it (`-x stable-only`) on non-stable SDKs,
// where the file is skipped at the parse phase before it is ever compiled.
// pqcrypto's KEM API returns Dart records, which this package's 2.19 language
// version cannot reference statically — those call sites go through `dynamic`
// so the file stays parseable by the 2.19 front end.
@Tags(['stable-only'])

import 'dart:typed_data' show Uint8List;

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:hashlib/random.dart';
import 'package:pqcrypto/pqcrypto.dart' as pqc;
import 'package:test/test.dart';

final levels = {
  MLKEM.kem512(): pqc.PqcKem.kyber512,
  MLKEM.kem768(): pqc.PqcKem.kyber768,
  MLKEM.kem1024(): pqc.PqcKem.kyber1024,
};

void main() {
  group('ML-KEM', () {
    test('pqcrypto: key generation from the same seed', () {
      levels.forEach((kem, other) {
        for (int i = 0; i < 10; ++i) {
          final seed = randomBytes(64);
          final keys = kem.keygen(seed: seed);
          final kp = (other as dynamic).generateKeyPair(seed);
          expect(toHex(kp.$1 as Uint8List), toHex(keys.encapsulationKey),
              reason: '${kem.name} ek [round: $i]');
          expect(toHex(kp.$2 as Uint8List), toHex(keys.decapsulationKey),
              reason: '${kem.name} dk [round: $i]');
        }
      });
    });
    test('pqcrypto: encapsulation from the same (ek, m)', () {
      levels.forEach((kem, other) {
        for (int i = 0; i < 10; ++i) {
          final keys = kem.keygen();
          final m = randomBytes(32);
          final enc = kem.$encaps(keys.encapsulationKey, m);
          final cs = (other as dynamic).encapsulate(keys.encapsulationKey, m);
          expect(toHex(cs.$1 as Uint8List), toHex(enc.cipherText),
              reason: '${kem.name} ct [round: $i]');
          expect(enc.sharedSecret.isEqual(cs.$2 as Uint8List), isTrue,
              reason: '${kem.name} ss [round: $i]');
        }
      });
    });
    test('pqcrypto: cross decapsulation', () {
      levels.forEach((kem, other) {
        for (int i = 0; i < 10; ++i) {
          final keys = kem.keygen();
          final enc = kem.encaps(keys.encapsulationKey);
          final ss = other.decapsulate(keys.decapsulationKey, enc.cipherText);
          expect(enc.sharedSecret.isEqual(ss), isTrue,
              reason: '${kem.name} [round: $i]');
        }
      });
    });
    test('pqcrypto: implicit rejection of a tampered cipher text', () {
      levels.forEach((kem, other) {
        for (int i = 0; i < 10; ++i) {
          final keys = kem.keygen();
          final enc = kem.encaps(keys.encapsulationKey);
          final bad = Uint8List.fromList(enc.cipherText);
          bad[i % bad.length] ^= 0xFF;
          // both must derive the same rejection secret J(z || ct)
          final r1 = kem.decaps(keys.decapsulationKey, bad);
          final r2 = other.decapsulate(keys.decapsulationKey, bad);
          expect(r1.isEqual(r2), isTrue, reason: '${kem.name} [round: $i]');
          expect(r1.isEqual(enc.sharedSecret), isFalse,
              reason: '${kem.name} [round: $i]');
        }
      });
    }, tags: ['vm-only']);
  });
}
