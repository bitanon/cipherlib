// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/random.dart';
import 'package:test/test.dart';

void main() {
  group('AEADCipher common behavior', () {
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
  });
}
