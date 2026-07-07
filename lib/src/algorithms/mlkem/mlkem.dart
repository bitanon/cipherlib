// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart'
    show HashDigest, Shake256, sha3_256, sha3_512;
import 'package:hashlib/random.dart' show randomBytes;

import '../../core/kem.dart';
import '../../utils/typed_data.dart';
import 'arith.dart';
import 'kpke.dart';

/// ML-KEM is a Module-Lattice-Based Key Encapsulation Mechanism, the primary
/// post-quantum key-establishment scheme standardized by NIST. Two parties
/// use it to agree on a 32-byte shared secret that is safe against attackers
/// with access to a quantum computer.
///
/// This implementation is based on the [FIPS 203: Module-Lattice-Based
/// Key-Encapsulation Mechanism Standard][fips] and its reference
/// implementation from the [pq-crystals/kyber][ref] project.
///
/// **Note:** This follows the constant-time structure of the reference
/// implementation, but Dart runtimes (JIT, AOT, dart2js) cannot guarantee
/// constant-time execution. Consider the deployment environment before
/// relying on it in side-channel-sensitive settings.
///
/// [fips]: https://doi.org/10.6028/NIST.FIPS.203
/// [ref]: https://github.com/pq-crystals/kyber
class MLKEM extends KEMBase {
  /// The lattice dimension parameter `k`
  final int k;

  /// The eta1 noise parameter for key generation
  final int eta1;

  /// The `d_u` ciphertext compression parameter
  final int du;

  /// The `d_v` ciphertext compression parameter
  final int dv;

  final KPKE _pke;

  const MLKEM._(this.k, this.eta1, this.du, this.dv, this._pke);

  /// ML-KEM-512 (FIPS 203, security category 1)
  factory MLKEM.kem512() => const MLKEM._(2, 3, 10, 4, KPKE(2, 3, 10, 4));

  /// ML-KEM-768 (FIPS 203, security category 3)
  factory MLKEM.kem768() => const MLKEM._(3, 2, 10, 4, KPKE(3, 2, 10, 4));

  /// ML-KEM-1024 (FIPS 203, security category 5)
  factory MLKEM.kem1024() => const MLKEM._(4, 2, 11, 5, KPKE(4, 2, 11, 5));

  @override
  String get name => 'ML-KEM-${k << 8}';

  @override
  int get encapsulationKeySize => 384 * k + 32;

  @override
  int get decapsulationKeySize => 768 * k + 96;

  @override
  int get cipherTextSize => 32 * (du * k + dv);

  @override
  int get sharedSecretSize => 32;

  @override
  int get seedSize => 64;

  /// Generates a [KEMKeyPair].
  ///
  /// If [seed] is `null`, a random one is drawn from a secure random
  /// generator. A [seed] of [seedSize] bytes is the concatenation `d || z`
  /// of FIPS 203 Section 3.3, which fully determines the key pair, the
  /// seed form is the standard way to store or transmit an ML-KEM key.
  ///
  /// Throws [ArgumentError] if a provided [seed] is not [seedSize] bytes.
  @override
  KEMKeyPair keygen({List<int>? seed}) {
    final s = seed == null
        ? randomBytes(seedSize)
        : validateLength('seed', seed, {seedSize});
    return $keygen(
      Uint8List.sublistView(s, 0, 32),
      Uint8List.sublistView(s, 32, 64),
    );
  }

  /// `ML-KEM.KeyGen_internal(d, z)` of FIPS 203 (Algorithm 16).
  ///
  /// Exposed for test vectors; use [keygen] instead.
  KEMKeyPair $keygen(List<int> d, List<int> z) {
    final d8 = validateLength('d', d, {32});
    final z8 = validateLength('z', z, {32});
    final ek = Uint8List(encapsulationKeySize);
    final dk = Uint8List(decapsulationKeySize);
    // dk = dk_PKE || ek || H(ek) || z
    _pke.$keygen(d8, ek, dk);
    dk.setRange(384 * k, 768 * k + 32, ek);
    dk.setRange(768 * k + 32, 768 * k + 64, sha3_256.convert(ek).bytes);
    dk.setRange(768 * k + 64, 768 * k + 96, z8);
    return KEMKeyPair(ek, dk);
  }

  /// Generates a shared secret and encapsulates it with the
  /// [encapsulationKey] of the other party.
  ///
  /// Throws [ArgumentError] if the [encapsulationKey] does not have
  /// [encapsulationKeySize] bytes, or if it fails the modulus check of
  /// FIPS 203 Section 7.2.
  @override
  KEMSecret encaps(List<int> encapsulationKey) =>
      $encaps(encapsulationKey, randomBytes(32));

  /// `ML-KEM.Encaps_internal(ek, m)` of FIPS 203 (Algorithm 17).
  ///
  /// Exposed for test vectors; use [encaps] instead, which draws [m] from a
  /// secure random generator as the standard requires.
  KEMSecret $encaps(List<int> encapsulationKey, List<int> m) {
    final ek = validateLength(
        'encapsulationKey', encapsulationKey, {encapsulationKeySize});
    final m8 = validateLength('m', m, {32});
    _checkModulus(ek);
    // (K, r) = G(m || H(ek))
    final buf = Uint8List(64);
    buf.setRange(0, 32, m8);
    buf.setRange(32, 64, sha3_256.convert(ek).bytes);
    final kr = sha3_512.convert(buf).bytes;
    final ct = Uint8List(cipherTextSize);
    _pke.$encrypt(ek, m8, Uint8List.sublistView(kr, 32, 64), ct);
    final ss = Uint8List.fromList(Uint8List.sublistView(kr, 0, 32));
    return KEMSecret(ct, HashDigest(ss));
  }

  /// Recovers the shared secret from the [cipherText] using the
  /// [decapsulationKey].
  ///
  /// A [cipherText] of valid length that was not produced for this key never
  /// throws; per FIPS 203 implicit rejection it yields a pseudo-random
  /// secret that does not match the sender's. This method does not perform
  /// the optional `H(ek)` consistency check of Section 7.1 on imported
  /// decapsulation keys; validate imported keys separately.
  ///
  /// Throws [ArgumentError] if the [decapsulationKey] or [cipherText]
  /// lengths are wrong.
  @override
  HashDigest decaps(List<int> decapsulationKey, List<int> cipherText) {
    // TODO: add a key-import validation API covering the H(ek) consistency
    // and modulus checks of FIPS 203 Section 7.1 in a future release.
    final dk = validateLength(
        'decapsulationKey', decapsulationKey, {decapsulationKeySize});
    final ct = validateLength('cipherText', cipherText, {cipherTextSize});
    final dkPke = Uint8List.sublistView(dk, 0, 384 * k);
    final ek = Uint8List.sublistView(dk, 384 * k, 768 * k + 32);
    final h = Uint8List.sublistView(dk, 768 * k + 32, 768 * k + 64);
    final z = Uint8List.sublistView(dk, 768 * k + 64, 768 * k + 96);

    // (K', r') = G(m' || h)
    final buf = Uint8List(64);
    _pke.$decrypt(dkPke, ct, buf);
    buf.setRange(32, 64, h);
    final kr = sha3_512.convert(buf).bytes;

    // re-encrypt and compare in constant time
    final cmp = Uint8List(cipherTextSize);
    _pke.$encrypt(
        ek,
        Uint8List.sublistView(buf, 0, 32), //
        Uint8List.sublistView(kr, 32, 64),
        cmp);
    final fail = $verify(ct, cmp, cipherTextSize);

    // rejection key K-bar = J(z || ct), computed unconditionally; the real
    // key overwrites it via a branch-free conditional move on success
    final sink = const Shake256(32).createSink();
    sink.add(z);
    sink.add(ct);
    final ss = sink.digest().bytes;
    _cmov(ss, kr, 32, 1 - fail);
    return HashDigest(ss);
  }

  /// The modulus check of FIPS 203 Section 7.2: every 12-bit coefficient of
  /// the encapsulation key must be less than 3329. This is equivalent to the
  /// `ek == ByteEncode12(ByteDecode12(ek))` round-trip of the standard,
  /// because a 12-bit value re-encodes to itself exactly when it is already
  /// reduced mod q.
  void _checkModulus(Uint8List ek) {
    int i, n = 384 * k;
    for (i = 0; i < n; i += 3) {
      if ((ek[i] | (ek[i + 1] << 8)) & 0xFFF >= 3329 ||
          ((ek[i + 1] >> 4) | (ek[i + 2] << 4)) & 0xFFF >= 3329) {
        throw ArgumentError.value(
            ek, 'encapsulationKey', 'modulus check failed');
      }
    }
  }

  /// Copies 32 bytes of [x] into [r] if `b` is 1, keeps [r] if `b` is 0,
  /// without branching on `b`. Ported from `cmov` (verify.c).
  static void _cmov(Uint8List r, Uint8List x, int len, int b) {
    int i;
    b = -b;
    for (i = 0; i < len; i++) {
      r[i] ^= b & (r[i] ^ x[i]);
    }
  }
}
