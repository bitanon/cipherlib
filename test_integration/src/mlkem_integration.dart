import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/hashlib.dart' show sha256;

import 'assertions.dart';

/// ML-KEM integration checks (known answer, round-trip, implicit rejection).
void runMlkemIntegration() {
  mlkemKnownAnswer();
  mlkemRoundTrip();
}

/// ML-KEM-768 key generation known-answer test from NIST ACVP-Server
/// (ML-KEM-keyGen-FIPS203/internalProjection.json, tcId 26, at commit
/// 15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0); the expected outputs are
/// compared through their SHA-256 digests to keep this file small.
void mlkemKnownAnswer() {
  print('----- ML-KEM-768 (known answer) -----');
  final d = fromHex(
      'e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0');
  final z = fromHex(
      '1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0');
  final keys = MLKEM.kem768().$keygen(d, z);
  final ekHash = sha256.convert(keys.encapsulationKey).hex();
  final dkHash = sha256.convert(keys.decapsulationKey).hex();
  if (ekHash !=
      '4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e') {
    throw StateError('ML-KEM keygen ek mismatch: $ekHash');
  }
  if (dkHash !=
      '7aab35839207f72b310abe36e2daa1cc7ff6f7fa8941e439967cd47d9b437079') {
    throw StateError('ML-KEM keygen dk mismatch: $dkHash');
  }
  print('keyGen vector: ok');
}

/// Round trip and implicit rejection through the public API for all levels.
void mlkemRoundTrip() {
  print('----- ML-KEM (round-trip all levels) -----');
  for (final kem in [MLKEM.kem512(), MLKEM.kem768(), MLKEM.kem1024()]) {
    final keys = kem.keygen();
    final enc = kem.encaps(keys.encapsulationKey);
    final ss = kem.decaps(keys.decapsulationKey, enc.cipherText);
    if (!ss.isEqual(enc.sharedSecret)) {
      throw StateError('${kem.name} shared secret mismatch');
    }
    final bad = Uint8List.fromList(enc.cipherText);
    bad[0] ^= 0xFF;
    final rejected = kem.decaps(keys.decapsulationKey, bad);
    if (rejected.isEqual(enc.sharedSecret)) {
      throw StateError('${kem.name} tampered cipher text was not rejected');
    }
    if (!bytesEq(enc.sharedSecret.bytes, ss.bytes)) {
      throw StateError('${kem.name} shared secret bytes mismatch');
    }
    print('${kem.name}: ok');
  }
}
