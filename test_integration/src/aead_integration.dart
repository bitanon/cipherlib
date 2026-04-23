import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

import 'assertions.dart';

void runAeadIntegration() {
  aeadRoundTrips();
  aeadWithAssociatedData();
  aeadWithExplicitCounter();
  aeadVerifyApis();
  emptyPayloads();
  badMacRejectedAllAead();
}

void aeadRoundTrips() {
  print('----- AEAD one-shot helpers -----');
  final payload = toUtf8('AEAD payload');

  final kc = randomBytes(32);
  final nc = randomBytes(12);
  final sc = chacha20poly1305(payload, kc, nonce: nc);
  final oc = chacha20poly1305(sc.data, kc, nonce: nc, mac: sc.mac.bytes);
  if (!bytesEq(oc.data, payload)) {
    throw StateError('ChaCha20-Poly1305 plaintext mismatch');
  }
  print('  ChaCha20-Poly1305: ok');

  final kx = randomBytes(32);
  final nx = randomBytes(24);
  final sx = xchacha20poly1305(payload, kx, nonce: nx);
  final ox = xchacha20poly1305(sx.data, kx, nonce: nx, mac: sx.mac.bytes);
  if (!bytesEq(ox.data, payload)) {
    throw StateError('XChaCha20-Poly1305 plaintext mismatch');
  }
  print('  XChaCha20-Poly1305: ok');

  final ks = randomBytes(32);
  final ns = randomBytes(8);
  final ss = salsa20poly1305(payload, ks, nonce: ns);
  final os = salsa20poly1305(ss.data, ks, nonce: ns, mac: ss.mac.bytes);
  if (!bytesEq(os.data, payload)) {
    throw StateError('Salsa20-Poly1305 plaintext mismatch');
  }
  print('  Salsa20-Poly1305: ok');

  final ku = randomBytes(32);
  final nu = randomBytes(24);
  final su = xsalsa20poly1305(payload, ku, nonce: nu);
  final ou = xsalsa20poly1305(su.data, ku, nonce: nu, mac: su.mac.bytes);
  if (!bytesEq(ou.data, payload)) {
    throw StateError('XSalsa20-Poly1305 plaintext mismatch');
  }
  print('  XSalsa20-Poly1305: ok');
  print('');
}

void aeadWithAssociatedData() {
  print('----- AEAD + AAD (class constructors) -----');
  final msg = toUtf8('secret');
  final aad = toUtf8('context');

  final key = randomBytes(32);
  final nonce12 = randomBytes(12);
  final sealed = ChaCha20(key, nonce12).poly1305(aad).sign(msg);
  final opened = chacha20poly1305(
    sealed.data,
    key,
    nonce: nonce12,
    mac: sealed.mac.bytes,
    aad: aad,
  );
  if (!bytesEq(opened.data, msg)) {
    throw StateError('ChaCha20Poly1305 + AAD mismatch');
  }

  final keyX = randomBytes(32);
  final nonce24 = randomBytes(24);
  final sx = XChaCha20(keyX, nonce24).poly1305(aad).sign(msg);
  final ox = xchacha20poly1305(
    sx.data,
    keyX,
    nonce: nonce24,
    mac: sx.mac.bytes,
    aad: aad,
  );
  if (!bytesEq(ox.data, msg)) {
    throw StateError('XChaCha20Poly1305 + AAD mismatch');
  }

  final ks = randomBytes(32);
  final ns = randomBytes(8);
  final ss = Salsa20(ks, ns).poly1305(aad).sign(msg);
  final os = salsa20poly1305(
    ss.data,
    ks,
    nonce: ns,
    mac: ss.mac.bytes,
    aad: aad,
  );
  if (!bytesEq(os.data, msg)) {
    throw StateError('Salsa20Poly1305 + AAD mismatch');
  }

  final kxs = randomBytes(32);
  final nxs = randomBytes(24);
  final sxs = XSalsa20(kxs, nxs).poly1305(aad).sign(msg);
  final oxs = xsalsa20poly1305(
    sxs.data,
    kxs,
    nonce: nxs,
    mac: sxs.mac.bytes,
    aad: aad,
  );
  if (!bytesEq(oxs.data, msg)) {
    throw StateError('XSalsa20Poly1305 + AAD mismatch');
  }

  print('  all AEAD+AAD paths: ok');
  print('');
}

void aeadWithExplicitCounter() {
  print('----- AEAD + Nonce64 counter -----');
  final payload = toUtf8('counter AEAD');
  final key = randomBytes(32);
  final nonce12 = randomBytes(12);
  final ctr = Nonce64.int64(42);
  final s1 = chacha20poly1305(payload, key, nonce: nonce12, counter: ctr);
  final o1 = chacha20poly1305(
    s1.data,
    key,
    nonce: nonce12,
    mac: s1.mac.bytes,
    counter: ctr,
  );
  if (!bytesEq(o1.data, payload)) {
    throw StateError('ChaCha20-Poly1305 + counter mismatch');
  }

  final nonce24 = randomBytes(24);
  final s2 = xchacha20poly1305(payload, key, nonce: nonce24, counter: ctr);
  final o2 = xchacha20poly1305(
    s2.data,
    key,
    nonce: nonce24,
    mac: s2.mac.bytes,
    counter: ctr,
  );
  if (!bytesEq(o2.data, payload)) {
    throw StateError('XChaCha20-Poly1305 + counter mismatch');
  }
  print('  ChaCha20 / XChaCha20 Poly1305: ok');
  print('');
}

void aeadVerifyApis() {
  print('----- AEADResult.verify / AEADCipher.verify -----');
  final msg = toUtf8('verify API');
  final key = randomBytes(32);
  final nonce = randomBytes(12);
  final algo = ChaCha20(key, nonce).poly1305();
  final sealed = algo.sign(msg);
  if (!sealed.verify(sealed.mac.bytes)) {
    throw StateError('AEADResult.verify(self) expected true');
  }
  if (!algo.verify(sealed.data, sealed.mac.bytes)) {
    throw StateError('AEADCipher.verify expected true');
  }
  final corrupt = Uint8List.fromList(sealed.mac.bytes)..[0] ^= 0xff;
  if (sealed.verify(corrupt)) {
    throw StateError('AEADResult.verify(corrupt) expected false');
  }
  if (algo.verify(sealed.data, corrupt)) {
    throw StateError('AEADCipher.verify(corrupt) expected false');
  }
  print('  ChaCha20Poly1305: ok');
  print('');
}

void emptyPayloads() {
  print('----- Empty plaintext -----');
  final key = randomBytes(32);
  final iv = randomBytes(16);
  final cbcCt = AES(key).cbc(iv).encryptString('');
  final cbcPt = AES(key).cbc(iv).decrypt(cbcCt);
  expectSameUtf8(cbcPt, '');

  final gcmIv = randomBytes(12);
  final gcm = AES(key).gcm(gcmIv);
  final gcmCt = gcm.encryptString('');
  final gcmPt = gcm.decrypt(gcmCt);
  expectSameUtf8(gcmPt, '');

  final n12 = randomBytes(12);
  final cp = chacha20poly1305([], key, nonce: n12);
  final op = chacha20poly1305(
    cp.data,
    key,
    nonce: n12,
    mac: cp.mac.bytes,
  );
  if (!bytesEq(op.data, const <int>[])) {
    throw StateError('empty ChaCha20-Poly1305 mismatch');
  }
  print('  CBC / GCM / ChaCha20-Poly1305: ok');
  print('');
}

void badMacRejectedAllAead() {
  print('----- AEAD bad MAC (all one-shot helpers) -----');

  void expectReject(void Function() run) {
    try {
      run();
      throw StateError('expected MAC verification failure');
    } on AssertionError {
      // legacy failure mode
    } on StateError catch (error) {
      if (error.message != 'Message authenticity check failed') {
        rethrow;
      }
    }
  }

  final k1 = randomBytes(32);
  final n12 = randomBytes(12);
  final g1 = chacha20poly1305([7], k1, nonce: n12);
  final b1 = Uint8List.fromList(g1.mac.bytes)..[0] ^= 0xff;
  expectReject(() => chacha20poly1305(g1.data, k1, nonce: n12, mac: b1));

  final k2 = randomBytes(32);
  final n24 = randomBytes(24);
  final g2 = xchacha20poly1305([8], k2, nonce: n24);
  final b2 = Uint8List.fromList(g2.mac.bytes)..[0] ^= 0xff;
  expectReject(() => xchacha20poly1305(g2.data, k2, nonce: n24, mac: b2));

  final k3 = randomBytes(32);
  final n8 = randomBytes(8);
  final g3 = salsa20poly1305([9], k3, nonce: n8);
  final b3 = Uint8List.fromList(g3.mac.bytes)..[0] ^= 0xff;
  expectReject(() => salsa20poly1305(g3.data, k3, nonce: n8, mac: b3));

  final k4 = randomBytes(32);
  final n24b = randomBytes(24);
  final g4 = xsalsa20poly1305([10], k4, nonce: n24b);
  final b4 = Uint8List.fromList(g4.mac.bytes)..[0] ^= 0xff;
  expectReject(() => xsalsa20poly1305(g4.data, k4, nonce: n24b, mac: b4));

  print('  ChaCha / XChaCha / Salsa / XSalsa Poly1305: ok');
  print('');
}
