import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

import 'assertions.dart';

void runStreamIntegration() {
  chacha20Variants();
  xchacha20Variants();
  salsa20Variants();
  xsalsa20Variants();
  resetIvBehaviors();
  xorRoundTrip();
}

void chacha20Variants() {
  print('----- ChaCha20 variants -----');
  const plain = 'stream cipher sample';
  final payload = toUtf8(plain);
  final key = randomBytes(32);

  final nonce8 = randomBytes(8);
  final nonce12 = randomBytes(12);
  final nonce16 = randomBytes(16);
  final ctr = Nonce64.int64(7);

  final c8 = chacha20(payload, key, nonce: nonce8, counter: ctr);
  final p8 = chacha20(c8, key, nonce: nonce8, counter: ctr);
  expectSameUtf8(p8, plain);

  final c12 = ChaCha20(key, nonce12, Nonce64.int32(3)).convert(payload);
  final p12 = ChaCha20(key, nonce12, Nonce64.int32(3)).convert(c12);
  expectSameUtf8(p12, plain);

  final c16 = chacha20(payload, key, nonce: nonce16);
  final p16 = chacha20(c16, key, nonce: nonce16);
  expectSameUtf8(p16, plain);

  print('  nonce 8/12/16 byte paths: ok');
  print('');
}

void xchacha20Variants() {
  print('----- XChaCha20 variants -----');
  const plain = 'xchacha stream sample';
  final payload = toUtf8(plain);
  final key = randomBytes(32);
  final ctr = Nonce64.int64(9);

  final nonce24 = randomBytes(24);
  final c24 = xchacha20(payload, key, nonce: nonce24, counter: ctr);
  final p24 = xchacha20(c24, key, nonce: nonce24, counter: ctr);
  expectSameUtf8(p24, plain);

  final nonce28 = randomBytes(28);
  final c28 = XChaCha20(key, nonce28, Nonce64.int32(11)).convert(payload);
  final p28 = XChaCha20(key, nonce28, Nonce64.int32(11)).convert(c28);
  expectSameUtf8(p28, plain);

  final nonce32 = randomBytes(32);
  final c32 = xchacha20(payload, key, nonce: nonce32);
  final p32 = xchacha20(c32, key, nonce: nonce32);
  expectSameUtf8(p32, plain);

  print('  nonce 24/28/32 byte paths: ok');
  print('');
}

void salsa20Variants() {
  print('----- Salsa20 variants -----');
  const plain = 'salsa stream sample';
  final payload = toUtf8(plain);
  final key = randomBytes(32);
  final ctr = Nonce64.int64(13);

  final nonce8 = randomBytes(8);
  final c8 = salsa20(payload, key, nonce: nonce8, counter: ctr);
  final p8 = salsa20(c8, key, nonce: nonce8, counter: ctr);
  expectSameUtf8(p8, plain);

  final nonce16 = randomBytes(16);
  final c16 = Salsa20(key, nonce16).convert(payload);
  final p16 = Salsa20(key, nonce16).convert(c16);
  expectSameUtf8(p16, plain);

  print('  nonce 8/16 byte paths: ok');
  print('');
}

void xsalsa20Variants() {
  print('----- XSalsa20 variants -----');
  const plain = 'xsalsa stream sample';
  final payload = toUtf8(plain);
  final key = randomBytes(32);
  final ctr = Nonce64.int64(17);

  final nonce24 = randomBytes(24);
  final c24 = xsalsa20(payload, key, nonce: nonce24, counter: ctr);
  final p24 = xsalsa20(c24, key, nonce: nonce24, counter: ctr);
  expectSameUtf8(p24, plain);

  final nonce32 = randomBytes(32);
  final c32 = XSalsa20(key, nonce32).convert(payload);
  final p32 = XSalsa20(key, nonce32).convert(c32);
  expectSameUtf8(p32, plain);

  print('  nonce 24/32 byte paths: ok');
  print('');
}

void resetIvBehaviors() {
  print('----- Salted cipher resetIV -----');
  final msg = toUtf8('same payload');

  final chacha = ChaCha20(randomBytes(32), randomBytes(12));
  final out1 = chacha.convert(msg);
  chacha.resetIV();
  final out2 = chacha.convert(msg);
  if (bytesEq(out1, out2)) {
    throw StateError('ChaCha20.resetIV expected a different output');
  }

  final xsalsa = XSalsa20(randomBytes(32), randomBytes(24)).poly1305();
  final sealed1 = xsalsa.sign(msg);
  xsalsa.resetIV();
  final sealed2 = xsalsa.sign(msg);
  if (bytesEq(sealed1.mac.bytes, sealed2.mac.bytes)) {
    throw StateError('XSalsa20Poly1305.resetIV expected a different tag');
  }

  print('  ChaCha20 / XSalsa20-Poly1305: ok');
  print('');
}

void xorRoundTrip() {
  print('----- XOR helper + class -----');
  final key = toUtf8('xor-key');
  final plain = toUtf8('XOR integration');

  final helperOut = xor(plain, key);
  final helperBack = xor(helperOut, key);
  if (!bytesEq(helperBack, plain)) {
    throw StateError('xor helper round-trip mismatch');
  }

  final cipher = XOR(key);
  final classOut = cipher.convert(plain);
  final classBack = cipher.convert(classOut);
  if (!bytesEq(classBack, plain)) {
    throw StateError('XOR class round-trip mismatch');
  }

  if (!bytesEq(helperOut, classOut)) {
    throw StateError('xor helper and XOR class output mismatch');
  }

  print('  helper/class round-trip parity: ok');
  print('');
}
