// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/cipherlib.dart';
import 'package:test/test.dart';

import 'utils.dart' show randomBytes;

void main() {
  group('AEADCipherSink', () {
    test(r'$add throws UnimplementedError', () {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final sink = ChaCha20Poly1305(key, nonce: nonce).createSink();
      expect(
        () => sink.$add([1, 2, 3], 0, 3),
        throwsA(isA<UnimplementedError>()),
      );
    });
  });
}
