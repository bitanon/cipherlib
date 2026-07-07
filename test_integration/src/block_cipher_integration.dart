import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

import 'assertions.dart';

/// Blowfish and Twofish integration checks (modes, known answers).
void runBlockCipherIntegration() {
  blowfishModesRoundTrip();
  blowfishKnownAnswer();
  twofishModesRoundTrip();
  twofishKnownAnswer();
}

/// Blowfish ECB/CBC/CTR encrypt + decrypt string paths.
void blowfishModesRoundTrip() {
  const plain = 'A not very secret message';
  final key = randomBytes(56);
  final iv = randomBytes(8);

  print('----- Blowfish (round-trip all modes) -----');
  final ecb = Blowfish(key).ecb().encryptString(plain);
  expectSameUtf8(Blowfish(key).ecb().decrypt(ecb), plain);
  print('ECB: ok');
  final cbc = Blowfish(key).cbc(iv).encryptString(plain);
  expectSameUtf8(Blowfish(key).cbc(iv).decrypt(cbc), plain);
  print('CBC: ok');
  final ctr = Blowfish(key).ctr(iv).encryptString(plain);
  expectSameUtf8(Blowfish(key).ctr(iv).decrypt(ctr), plain);
  print('CTR: ok');
}

/// Blowfish known-answer test by Eric Young:
/// https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt
void blowfishKnownAnswer() {
  print('----- Blowfish (known answer) -----');
  final key = fromHex('FEDCBA9876543210');
  final plain = fromHex('0123456789ABCDEF');
  final cipher = Blowfish.noPadding(key).ecb().encrypt(plain);
  if (!bytesEq(cipher, fromHex('0ACEAB0FC6A0A28D'))) {
    throw StateError('Blowfish known answer mismatch: ${toHex(cipher)}');
  }
  print('ECB vector: ok');
}

/// Twofish ECB/CBC/CTR encrypt + decrypt string paths.
void twofishModesRoundTrip() {
  const plain = 'A not very secret message';
  final key = randomBytes(32);
  final iv = randomBytes(16);

  print('----- Twofish (round-trip all modes) -----');
  final ecb = Twofish(key).ecb().encryptString(plain);
  expectSameUtf8(Twofish(key).ecb().decrypt(ecb), plain);
  print('ECB: ok');
  final cbc = Twofish(key).cbc(iv).encryptString(plain);
  expectSameUtf8(Twofish(key).cbc(iv).decrypt(cbc), plain);
  print('CBC: ok');
  final ctr = Twofish(key).ctr(iv).encryptString(plain);
  expectSameUtf8(Twofish(key).ctr(iv).decrypt(ctr), plain);
  print('CTR: ok');
}

/// Twofish known-answer test:
/// https://www.schneier.com/code/ecb_ival.txt
void twofishKnownAnswer() {
  print('----- Twofish (known answer) -----');
  final key = fromHex('00000000000000000000000000000000');
  final plain = fromHex('00000000000000000000000000000000');
  final cipher = Twofish.noPadding(key).ecb().encrypt(plain);
  if (!bytesEq(cipher, fromHex('9F589F5CF6122C32B6BFEC2F2AE8C35A'))) {
    throw StateError('Twofish known answer mismatch: ${toHex(cipher)}');
  }
  print('ECB vector: ok');
}
