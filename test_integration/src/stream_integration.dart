import 'dart:async';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

import 'assertions.dart';

Future<void> runStreamIntegration() async {
  xorApis();
  await streamCipherStreams();
  await streamCipherWithCounter();
  await cipherBindMatchesConvert();
  streamCipherBuffers();
  chacha20ShortKey();
  chacha20SixteenByteNonce();
  salsa20LongNonce();
}

void xorApis() {
  print('----- XOR -----');
  final key = randomBytes(11);
  final msg = toUtf8('stream xor demo');
  final ct = xor(msg, key);
  if (!bytesEq(XOR(key).convert(msg), ct)) {
    throw StateError('XOR class vs top-level xor mismatch');
  }
  final pt = xor(ct, key);
  if (!bytesEq(pt, msg)) {
    throw StateError('XOR round-trip failed');
  }
  print('  round-trip: ok');
  print('');
}

Future<void> streamCipherStreams() async {
  print('----- stream APIs (chunked) -----');
  final message = List<int>.generate(500, (i) => i & 255);

  Future<void> checkStream(
    String label,
    Stream<int> Function(Stream<int>, List<int>, {List<int>? nonce}) streamFn,
    Uint8List Function(List<int>, List<int>, {List<int>? nonce}) bufFn,
    List<int> key,
    List<int> nonce,
  ) async {
    final direct = bufFn(message, key, nonce: nonce);
    final out = await streamFn(
      Stream<int>.fromIterable(message),
      key,
      nonce: nonce,
    ).fold<List<int>>(<int>[], (p, e) => p..add(e));
    if (!bytesEq(out, direct)) {
      throw StateError('$label stream vs buffer mismatch');
    }
    print('  $label: ok');
  }

  await checkStream(
    'ChaCha20',
    chacha20Stream,
    chacha20,
    randomBytes(32),
    randomBytes(12),
  );
  await checkStream(
    'XChaCha20',
    xchacha20Stream,
    xchacha20,
    randomBytes(32),
    randomBytes(24),
  );
  await checkStream(
    'Salsa20',
    salsa20Stream,
    salsa20,
    randomBytes(32),
    randomBytes(8),
  );
  await checkStream(
    'XSalsa20',
    xsalsa20Stream,
    xsalsa20,
    randomBytes(32),
    randomBytes(24),
  );
  print('');
}

/// Stream helpers honor Nonce64 counter (matches buffer API).
Future<void> streamCipherWithCounter() async {
  print('----- stream APIs + Nonce64 counter -----');
  final message = List<int>.generate(300, (i) => i & 255);
  final key = randomBytes(32);
  final ctr = Nonce64.int64(11);

  Future<void> check(
    String label,
    List<int> nonce,
    Stream<int> Function(Stream<int>, List<int>,
            {List<int>? nonce, Nonce64? counter})
        streamFn,
    Uint8List Function(List<int>, List<int>,
            {List<int>? nonce, Nonce64? counter})
        bufFn,
  ) async {
    final direct = bufFn(message, key, nonce: nonce, counter: ctr);
    final out = await streamFn(
      Stream<int>.fromIterable(message),
      key,
      nonce: nonce,
      counter: ctr,
    ).fold<List<int>>(<int>[], (p, e) => p..add(e));
    if (!bytesEq(out, direct)) {
      throw StateError('$label stream counter vs buffer mismatch');
    }
    print('  $label: ok');
  }

  await check('ChaCha20', randomBytes(12), chacha20Stream, chacha20);
  await check('XChaCha20', randomBytes(24), xchacha20Stream, xchacha20);
  await check('Salsa20', randomBytes(8), salsa20Stream, salsa20);
  await check('XSalsa20', randomBytes(24), xsalsa20Stream, xsalsa20);
  print('');
}

/// `Cipher.bind` applies convert per chunk; one chunk equals convert.
Future<void> cipherBindMatchesConvert() async {
  print('----- Cipher.bind (matches convert for one chunk) -----');
  final ck = randomBytes(32);
  final cn = randomBytes(12);
  final cha = ChaCha20(ck, cn);
  final buf = List<int>.generate(120, (i) => i & 255);
  final direct = cha.convert(buf);
  final streamed = await cha
      .bind(Stream<List<int>>.fromIterable([buf]))
      .fold<List<int>>(<int>[], (a, b) => a..addAll(b));
  if (!bytesEq(direct, streamed)) {
    throw StateError('ChaCha20 bind diverged from convert');
  }

  final xk = randomBytes(11);
  final xor = XOR(xk);
  final xd = xor.convert(buf);
  final xs = await xor
      .bind(Stream<List<int>>.fromIterable([buf]))
      .fold<List<int>>(<int>[], (a, b) => a..addAll(b));
  if (!bytesEq(xd, xs)) {
    throw StateError('XOR bind diverged from convert');
  }
  print('  ChaCha20 / XOR: ok');
  print('');
}

void streamCipherBuffers() {
  print('----- stream ciphers (buffer) + Nonce64 -----');
  final msg = toUtf8('nonce counter demo');
  final k32 = randomBytes(32);
  final nCha = randomBytes(12);
  final ctr = Nonce64.int64(7);

  final c1 = chacha20(msg, k32, nonce: nCha, counter: ctr);
  final c2 = chacha20(c1, k32, nonce: nCha, counter: ctr);
  if (!bytesEq(c2, msg)) {
    throw StateError('ChaCha20 counter round-trip failed');
  }

  final xk = randomBytes(32);
  final xn = randomBytes(24);
  final x1 = xchacha20(msg, xk, nonce: xn);
  final x2 = xchacha20(x1, xk, nonce: xn);
  if (!bytesEq(x2, msg)) {
    throw StateError('XChaCha20 round-trip failed');
  }

  final sk = randomBytes(32);
  final sn = randomBytes(8);
  final s1 = salsa20(msg, sk, nonce: sn);
  final s2 = salsa20(s1, sk, nonce: sn);
  if (!bytesEq(s2, msg)) {
    throw StateError('Salsa20 round-trip failed');
  }

  final uxk = randomBytes(32);
  final uxn = randomBytes(24);
  final u1 = xsalsa20(msg, uxk, nonce: uxn);
  final u2 = xsalsa20(u1, uxk, nonce: uxn);
  if (!bytesEq(u2, msg)) {
    throw StateError('XSalsa20 round-trip failed');
  }
  print('  symmetric encrypt/decrypt: ok');
  print('');
}

void chacha20ShortKey() {
  print('----- ChaCha20 (128-bit key / 96-bit nonce) -----');
  final msg = toUtf8('short key');
  final key16 = randomBytes(16);
  final nonce = randomBytes(12);
  final c = chacha20(msg, key16, nonce: nonce);
  final p = chacha20(c, key16, nonce: nonce);
  if (!bytesEq(p, msg)) {
    throw StateError('ChaCha20 128-bit key round-trip failed');
  }
  print('  round-trip: ok');
  print('');

  print('----- ChaCha20 (64-bit nonce) -----');
  final msg8 = toUtf8('ietf compat');
  final key = randomBytes(32);
  final nonce8 = randomBytes(8);
  final cx = chacha20(msg8, key, nonce: nonce8);
  final px = chacha20(cx, key, nonce: nonce8);
  if (!bytesEq(px, msg8)) {
    throw StateError('ChaCha20 8-byte nonce round-trip failed');
  }
  print('  round-trip: ok');
  print('');
}

void chacha20SixteenByteNonce() {
  print('----- ChaCha20 (128-bit nonce, raw) -----');
  final msg = toUtf8('raw 16 byte nonce');
  final key = randomBytes(32);
  final nonce16 = randomBytes(16);
  final c = chacha20(msg, key, nonce: nonce16);
  final p = chacha20(c, key, nonce: nonce16);
  if (!bytesEq(p, msg)) {
    throw StateError('ChaCha20 16-byte nonce round-trip failed');
  }
  print('  round-trip: ok');
  print('');
}

void salsa20LongNonce() {
  print('----- Salsa20 (128-bit nonce) -----');
  final msg = toUtf8('wide nonce');
  final key = randomBytes(32);
  final nonce = randomBytes(16);
  final c = salsa20(msg, key, nonce: nonce);
  final p = salsa20(c, key, nonce: nonce);
  if (!bytesEq(p, msg)) {
    throw StateError('Salsa20 16-byte nonce round-trip failed');
  }
  print('  round-trip: ok');
  print('');
}
