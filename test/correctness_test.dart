// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/random.dart';
import 'package:test/test.dart';

const R = randomBytes;
const rand = 'random';

class P {
  const P(this._internal);
  final List<dynamic> _internal;
  @override
  String toString() => _internal.map((x) => '$x').join('/');
}

void main() {
  final ciphers = <P, dynamic>{};

  // Test messages
  final messages = [
    ...List.generate(25, (i) => i), // 0 to 24
    16, 44, 64, 256, 2040, 3192, 5050, 124568
  ].map(R).toList();

  // 64-bit random counter
  final C = Nonce64.random();

  // Additional authenticated data
  final aadsList = [0, 1, 3, 9, 15, 16, 17, 32, 63, 229].map(R).toList();

  // Padding schemes
  final paddingList = [Padding.byte, Padding.ansi, Padding.pkcs7];

  // ------------------------------------------------------------
  // XOR
  // ------------------------------------------------------------
  for (int i = 1; i < 10; i <<= 1) {
    ciphers.addAll({
      P([i]): XOR(R(i << 1)),
    });
  }
  // ------------------------------------------------------------
  // Salsa20
  // ------------------------------------------------------------
  for (final k in [16, 32]) {
    ciphers.addAll({
      P([k, null, null]): Salsa20(R(k)),
      P([k, 8, null]): Salsa20(R(k), R(8)),
      P([k, 16, null]): Salsa20(R(k), R(16)),
      P([k, 8, rand]): Salsa20(R(k), R(8), C),
      P([k, null, rand]): Salsa20(R(k), null, C),
    });
  }
  // ------------------------------------------------------------
  // XSalsa20
  // ------------------------------------------------------------
  for (final k in [16, 32]) {
    ciphers.addAll({
      P([k, null, null]): XSalsa20(R(k)),
      P([k, 24, null]): XSalsa20(R(k), R(24)),
      P([k, 32, null]): XSalsa20(R(k), R(32)),
      P([k, 24, rand]): XSalsa20(R(k), R(24), C),
      P([k, null, rand]): XSalsa20(R(k), null, C),
    });
  }
  // ------------------------------------------------------------
  // Salsa20-Poly1305
  // ------------------------------------------------------------
  for (final k in [16, 32]) {
    ciphers.addAll({
      P([k, null, null]): Salsa20(R(k)).poly1305(),
      P([k, 8, null]): Salsa20(R(k), R(8)).poly1305(),
      P([k, 16, null]): Salsa20(R(k), R(16)).poly1305(),
      P([k, 8, rand]): Salsa20(R(k), R(8), C).poly1305(),
      P([k, null, rand]): Salsa20(R(k), null, C).poly1305(),
    });
  }
  // ------------------------------------------------------------
  // XSalsa20-Poly1305
  // ------------------------------------------------------------
  for (final k in [16, 32]) {
    ciphers.addAll({
      P([k, null, null]): XSalsa20(R(k)).poly1305(),
      P([k, 24, null]): XSalsa20(R(k), R(24)).poly1305(),
      P([k, 32, null]): XSalsa20(R(k), R(32)).poly1305(),
      P([k, 24, rand]): XSalsa20(R(k), R(24), C).poly1305(),
      P([k, null, rand]): XSalsa20(R(k), null, C).poly1305(),
    });
  }
  // ------------------------------------------------------------
  // ChaCha20
  // ------------------------------------------------------------
  for (final k in [16, 32]) {
    ciphers.addAll({
      P([k, null, null]): ChaCha20(R(k)),
      P([k, 8, null]): ChaCha20(R(k), R(8)),
      P([k, 12, null]): ChaCha20(R(k), R(12)),
      P([k, 16, null]): ChaCha20(R(k), R(16)),
      P([k, 8, rand]): ChaCha20(R(k), R(8), C),
      P([k, 12, rand]): ChaCha20(R(k), R(12), C),
      P([k, null, rand]): ChaCha20(R(k), null, C),
    });
  }
  // ------------------------------------------------------------
  // XChaCha20
  // ------------------------------------------------------------
  for (final k in [16, 32]) {
    ciphers.addAll({
      P([k, null, null]): XChaCha20(R(k)),
      P([k, 24, null]): XChaCha20(R(k), R(24)),
      P([k, 28, null]): XChaCha20(R(k), R(28)),
      P([k, 32, null]): XChaCha20(R(k), R(32)),
      P([k, 24, rand]): XChaCha20(R(k), R(24), C),
      P([k, 28, rand]): XChaCha20(R(k), R(28), C),
      P([k, null, rand]): XChaCha20(R(k), null, C),
    });
  }
  // ------------------------------------------------------------
  // ChaCha20-Poly1305
  // ------------------------------------------------------------
  for (final k in [16, 32]) {
    ciphers.addAll({
      P([k, null, null]): ChaCha20(R(k)).poly1305(),
      P([k, 8, null]): ChaCha20(R(k), R(8)).poly1305(),
      P([k, 12, null]): ChaCha20(R(k), R(12)).poly1305(),
      P([k, 16, null]): ChaCha20(R(k), R(16)).poly1305(),
      P([k, 8, rand]): ChaCha20(R(k), R(8), C).poly1305(),
      P([k, 12, rand]): ChaCha20(R(k), R(12), C).poly1305(),
      P([k, null, rand]): ChaCha20(R(k), null, C).poly1305(),
    });
  }
  // ------------------------------------------------------------
  // XChaCha20-Poly1305
  // ------------------------------------------------------------
  for (final k in [16, 32]) {
    ciphers.addAll({
      P([k, null, null]): XChaCha20(R(k)).poly1305(),
      P([k, 24, null]): XChaCha20(R(k), R(24)).poly1305(),
      P([k, 28, null]): XChaCha20(R(k), R(28)).poly1305(),
      P([k, 32, null]): XChaCha20(R(k), R(32)).poly1305(),
      P([k, 24, rand]): XChaCha20(R(k), R(24), C).poly1305(),
      P([k, 28, rand]): XChaCha20(R(k), R(28), C).poly1305(),
      P([k, null, rand]): XChaCha20(R(k), null, C).poly1305(),
    });
  }
  // ------------------------------------------------------------
  // AES-CBC
  // ------------------------------------------------------------
  for (final p in paddingList) {
    for (final k in [16, 24, 32]) {
      ciphers.addAll({
        P([k, p.name]): AES(R(k), p).cbc(R(16)),
      });
    }
  }
  // ------------------------------------------------------------
  // AES-CFB
  // ------------------------------------------------------------
  for (final k in [16, 24, 32]) {
    for (final b in [1, 5, 8, 11, 16]) {
      ciphers.addAll({
        P([k, b]): AES(R(k)).cfb(R(16), b),
      });
    }
  }
  // ------------------------------------------------------------
  // AES-CTR
  // ------------------------------------------------------------
  for (final k in [16, 24, 32]) {
    for (final c in [1, 13, 64, 43, 128]) {
      ciphers.addAll({
        P([k, c]): AES(R(k)).ctr(R(16), c),
      });
    }
  }
  // ------------------------------------------------------------
  // AES-ECB
  // ------------------------------------------------------------
  for (final p in paddingList) {
    for (final k in [16, 24, 32]) {
      ciphers.addAll({
        P([k, p.name]): AES(R(k), p).ecb(),
      });
    }
  }
  // ------------------------------------------------------------
  // AES-GCM
  // ------------------------------------------------------------
  for (final k in [16, 24, 32]) {
    for (final t in [1, 5, 8, 11, 16]) {
      for (final A in [null, ...aadsList]) {
        final ts = 'tag=$t';
        final al = 'aad=${A?.length}';
        ciphers.addAll({
          P([k, 0, ts, al]): AES(R(k)).gcm(R(0), tagSize: t, aad: A),
          P([k, 16, ts, al]): AES(R(k)).gcm(R(16), tagSize: t, aad: A),
          P([k, 32, ts, al]): AES(R(k)).gcm(R(128), tagSize: t, aad: A),
        });
      }
    }
  }
  // ------------------------------------------------------------
  // AES-IGE
  // ------------------------------------------------------------
  for (final p in paddingList) {
    for (final k in [16, 24, 32]) {
      ciphers.addAll({
        P([k, 16, p.name]): AES(R(k), p).ige(R(16)),
        P([k, 32, p.name]): AES(R(k), p).ige(R(32)),
      });
    }
  }
  // ------------------------------------------------------------
  // AES-OFB
  // ------------------------------------------------------------
  for (final k in [16, 24, 32]) {
    for (final b in [1, 5, 8, 11, 16]) {
      ciphers.addAll({
        P([k, b]): AES(R(k)).ofb(R(16), b),
      });
    }
  }
  // ------------------------------------------------------------
  // AES-PCBC
  // ------------------------------------------------------------
  for (final p in paddingList) {
    for (final k in [16, 24, 32]) {
      ciphers.addAll({
        P([k, p.name]): AES(R(k), p).pcbc(R(16)),
      });
    }
  }
  // ------------------------------------------------------------
  // AES-XTS
  // ------------------------------------------------------------
  for (final k in [32, 48, 64]) {
    ciphers.addAll({
      P([k, 16]): AES(R(k), Padding.none).xts(R(16)),
    });
  }

  // ------------------------------------------------------------
  // Test all ciphers
  // ------------------------------------------------------------
  for (final entry in ciphers.entries) {
    final cipher = entry.value;
    if (cipher is AEADCipher) {
      test('sign and verify: ${cipher.name}: ${entry.key} with AAD', () {
        for (final message in messages) {
          for (final aad in [null, ...aadsList]) {
            final sealed = cipher.sign(message, aad);
            final verified = cipher.verify(sealed.data, sealed.mac.bytes, aad);
            expect(
              verified,
              isTrue,
              reason: '[size: ${message.length}, aad: ${aad?.length}]',
            );
          }
        }
      });
    } else {
      Uint8List encrypted, decrypted;
      test('encrypt <-> decrypt: ${cipher.name}: ${entry.key}', () {
        for (final message in messages) {
          if (cipher is AESInXTSMode && message.length < 16) {
            continue;
          }
          if (cipher is CollateCipher) {
            encrypted = cipher.encrypt(message);
            decrypted = cipher.decrypt(encrypted);
          } else {
            encrypted = cipher.convert(message);
            decrypted = cipher.convert(encrypted);
          }
          expect(decrypted, equals(message),
              reason: '[size: ${message.length}]');
        }
      });
    }
  }
}
