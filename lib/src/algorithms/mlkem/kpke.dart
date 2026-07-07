// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show Shake128, Shake256, sha3_512;

import 'mlkem_core.dart';

/// The K-PKE component scheme of FIPS 203 (Section 5).
///
/// K-PKE is not IND-CCA secure on its own and must only be used through the
/// ML-KEM layer. Ported from `indcpa.c` of the reference implementation.
class KPKE {
  /// The lattice dimension parameter `k`
  final int k;

  /// The eta1 noise parameter for key generation
  final int eta1;

  /// The `d_u` ciphertext compression parameter
  final int du;

  /// The `d_v` ciphertext compression parameter
  final int dv;

  const KPKE(this.k, this.eta1, this.du, this.dv);

  /// Byte length of the K-PKE public key (FIPS 203: `ek_PKE`)
  int get publicKeyBytes => 384 * k + 32;

  /// Byte length of the K-PKE secret key (FIPS 203: `dk_PKE`)
  int get secretKeyBytes => 384 * k;

  /// Byte length of the K-PKE ciphertext
  int get cipherTextBytes => 32 * (du * k + dv);

  // SHAKE256 as the PRF of FIPS 203: eta * 64 output bytes
  static const Shake256 _prf128 = Shake256(128);
  static const Shake256 _prf192 = Shake256(192);

  /// Expands [rho] into the `k x k` matrix A (or its transpose) by rejection
  /// sampling on SHAKE128 output. Ported from `gen_matrix` (indcpa.c).
  ///
  /// One sink is reused across all entries via `reset()`; each `$update()`
  /// squeezes the next `blockLength` (168) bytes into `buffer`. Only that
  /// prefix of the 200-byte state buffer is squeezed output.
  void _genMatrix(Int16List a, Uint8List rho, bool transposed) {
    int i, j, ctr, off;
    final xof = const Shake128(0).createSink();
    final xy = Uint8List(2);
    for (i = 0; i < k; ++i) {
      for (j = 0; j < k; ++j) {
        if (transposed) {
          xy[0] = i;
          xy[1] = j;
        } else {
          xy[0] = j;
          xy[1] = i;
        }
        xof.reset();
        xof.add(rho);
        xof.add(xy);
        xof.$finalize();
        off = (i * k + j) << 8;
        ctr = $rejUniform(a, off, 0, xof.buffer, xof.blockLength);
        while (ctr < 256) {
          xof.$update();
          ctr = $rejUniform(a, off, ctr, xof.buffer, xof.blockLength);
        }
      }
    }
  }

  /// Samples a CBD polynomial at [off] using `PRF(seed, nonce)`.
  /// [seed33] is a 33-byte scratch holding the seed in bytes 0..31;
  /// byte 32 is overwritten with [nonce].
  void _getNoise(Int16List r, int off, Uint8List seed33, int nonce, int eta) {
    seed33[32] = nonce;
    final buf = (eta == 3 ? _prf192 : _prf128).convert(seed33).bytes;
    $cbd(r, off, buf, eta);
  }

  /// K-PKE key generation from the 32-byte seed [d], writing the public key
  /// into [ek] and the secret key into [dk].
  ///
  /// Ported from `indcpa_keypair_derand` (indcpa.c); note the FIPS 203
  /// domain separation `(rho, sigma) = G(d || k)`.
  void $keygen(Uint8List d, Uint8List ek, Uint8List dk) {
    int i, nonce;

    final gin = Uint8List(33);
    gin.setRange(0, 32, d);
    gin[32] = k;
    final g = sha3_512.convert(gin).bytes;
    final rho = Uint8List.sublistView(g, 0, 32);
    final seed33 = Uint8List(33); // sigma || nonce
    seed33.setRange(0, 32, g, 32);

    final a = Int16List((k * k) << 8);
    _genMatrix(a, rho, false);

    nonce = 0;
    final skpv = Int16List(k << 8);
    final e = Int16List(k << 8);
    for (i = 0; i < k; ++i) {
      _getNoise(skpv, i << 8, seed33, nonce++, eta1);
    }
    for (i = 0; i < k; ++i) {
      _getNoise(e, i << 8, seed33, nonce++, eta1);
    }

    for (i = 0; i < k; ++i) {
      $ntt(skpv, i << 8);
    }
    for (i = 0; i < k; ++i) {
      $ntt(e, i << 8);
    }

    final pkpv = Int16List(k << 8);
    for (i = 0; i < k; ++i) {
      $basemulAcc(pkpv, i << 8, a, (i * k) << 8, skpv, 0, k);
      $toMont(pkpv, i << 8);
    }
    $add(pkpv, 0, e, 0, k << 8);
    $reduce(pkpv, 0, k << 8);

    for (i = 0; i < k; ++i) {
      $polyToBytes(dk, i * 384, skpv, i << 8);
    }
    for (i = 0; i < k; ++i) {
      $polyToBytes(ek, i * 384, pkpv, i << 8);
    }
    ek.setRange(384 * k, 384 * k + 32, rho);
  }

  /// K-PKE encryption of the 32-byte message [m] under the public key [ek],
  /// with all randomness derived from the 32-byte seed [coins]; writes the
  /// ciphertext into [ct]. Ported from `indcpa_enc` (indcpa.c).
  void $encrypt(Uint8List ek, Uint8List m, Uint8List coins, Uint8List ct) {
    int i, nonce;

    final pkpv = Int16List(k << 8);
    for (i = 0; i < k; ++i) {
      $polyFromBytes(pkpv, i << 8, ek, i * 384);
    }
    final rho = Uint8List.sublistView(ek, 384 * k, 384 * k + 32);

    final kp = Int16List(256);
    $polyFromMsg(kp, 0, m, 0);

    final at = Int16List((k * k) << 8);
    _genMatrix(at, rho, true);

    final seed33 = Uint8List(33);
    seed33.setRange(0, 32, coins);

    // nonce order is KAT-critical: sp gets 0..k-1 (eta1), ep gets k..2k-1
    // (eta2), epp gets 2k (eta2)
    nonce = 0;
    final sp = Int16List(k << 8);
    final ep = Int16List(k << 8);
    final epp = Int16List(256);
    for (i = 0; i < k; ++i) {
      _getNoise(sp, i << 8, seed33, nonce++, eta1);
    }
    for (i = 0; i < k; ++i) {
      _getNoise(ep, i << 8, seed33, nonce++, 2);
    }
    _getNoise(epp, 0, seed33, nonce++, 2);

    for (i = 0; i < k; ++i) {
      $ntt(sp, i << 8);
    }

    final b = Int16List(k << 8);
    for (i = 0; i < k; ++i) {
      $basemulAcc(b, i << 8, at, (i * k) << 8, sp, 0, k);
    }
    final v = Int16List(256);
    $basemulAcc(v, 0, pkpv, 0, sp, 0, k);

    for (i = 0; i < k; ++i) {
      $invntt(b, i << 8);
    }
    $invntt(v, 0);

    $add(b, 0, ep, 0, k << 8);
    $add(v, 0, epp, 0, 256);
    $add(v, 0, kp, 0, 256);
    $reduce(b, 0, k << 8);
    $reduce(v, 0, 256);

    if (du == 10) {
      $vecCompress10(ct, 0, b, k);
      $polyCompress4(ct, 320 * k, v, 0);
    } else {
      $vecCompress11(ct, 0, b, k);
      $polyCompress5(ct, 352 * k, v, 0);
    }
  }

  /// K-PKE decryption of the ciphertext [ct] under the secret key [dk],
  /// writing the 32-byte message into [m].
  /// Ported from `indcpa_dec` (indcpa.c).
  void $decrypt(Uint8List dk, Uint8List ct, Uint8List m) {
    int i;

    final b = Int16List(k << 8);
    final v = Int16List(256);
    if (du == 10) {
      $vecDecompress10(b, ct, 0, k);
      $polyDecompress4(v, 0, ct, 320 * k);
    } else {
      $vecDecompress11(b, ct, 0, k);
      $polyDecompress5(v, 0, ct, 352 * k);
    }

    final skpv = Int16List(k << 8);
    for (i = 0; i < k; ++i) {
      $polyFromBytes(skpv, i << 8, dk, i * 384);
    }

    for (i = 0; i < k; ++i) {
      $ntt(b, i << 8);
    }
    final mp = Int16List(256);
    $basemulAcc(mp, 0, skpv, 0, b, 0, k);
    $invntt(mp, 0);

    $subFrom(mp, 0, v, 0, 256); // mp = v - mp
    $reduce(mp, 0, 256);
    $polyToMsg(m, 0, mp, 0);
  }
}
