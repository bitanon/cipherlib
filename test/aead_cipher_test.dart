// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/random.dart';
import 'package:test/test.dart';

void main() {
  group('AEADCipher common behavior', () {
    test('cast is unsupported for AEAD ciphers', () {
      final algo = ChaCha20(Uint8List(32), Uint8List(12)).poly1305();
      expect(
        () => algo.cast<List<int>, Uint8List>(),
        throwsUnsupportedError,
      );
    });

    test('AEADResult.withIV creates a result with provided nonce', () {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final payload = randomBytes(17);

      final signed = ChaCha20(key, nonce).poly1305().sign(payload);
      final customIv = Uint8List.fromList(List<int>.filled(24, 5));
      final withIv = signed.withIV(customIv);

      expect(withIv.data, equals(signed.data));
      expect(withIv.mac.bytes, equals(signed.mac.bytes));
      expect(withIv.iv, equals(customIv));
    });

    test('AEADResult.verify rejects null digest', () {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final sealed = chacha20poly1305([1, 2, 3], key, nonce: nonce);

      expect(sealed.verify(null), isFalse);
    });

    test('bind delegates conversion over list chunks', () async {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final algo = ChaCha20(key, nonce).poly1305();
      final input = <List<int>>[
        [1, 2, 3, 4],
        [5, 6],
      ];

      final out =
          await algo.bind(Stream<List<int>>.fromIterable(input)).toList();

      expect(out.length, equals(2));
      expect(out[0].length, equals(4));
      expect(out[1].length, equals(2));
    });

    test('stream delegates conversion over int stream', () async {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final algo = ChaCha20(key, nonce).poly1305();
      final plain = randomBytes(33);

      final out =
          await algo.stream(Stream<int>.fromIterable(plain), 8).toList();

      expect(out.length, equals(plain.length));
    });
  });
}
