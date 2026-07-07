// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'arith.dart';

// Polynomial arithmetic for ML-KEM over Z_3329[X]/(X^256 + 1), ported from
// the reference implementation of FIPS 203 (https://github.com/pq-crystals/kyber).
//
// A polynomial is 256 coefficients in an [Int16List]; vectors and matrices
// are flat [Int16List]s addressed with element offsets, mirroring the C
// pointer arithmetic. Int16List writes truncate to 16 bits exactly like the
// C `int16_t` stores, so any bound violation fails identically to the
// reference instead of silently diverging. All intermediate arithmetic runs
// in plain `int` locals; per-site comments justify the platform-sensitive
// bit operations.

/// Precomputed powers of the primitive root of unity 17, in Montgomery form
/// and bit-reversed order. Copied verbatim from `zetas[128]` (ntt.c).
const List<int> _zetas = <int>[
  -1044, -758, -359, -1517, 1493, 1422, 287, 202, //
  -171, 622, 1577, 182, 962, -1202, -1474, 1468,
  573, -1325, 264, 383, -829, 1458, -1602, -130,
  -681, 1017, 732, 608, -1542, 411, -205, -1571,
  1223, 652, -552, 1015, -1293, 1491, -282, -1544,
  516, -8, -320, -666, -1618, -1162, 126, 1469,
  -853, -90, -271, 830, 107, -1421, -247, -951,
  -398, 961, -1508, -725, 448, -1065, 677, -1275,
  -1103, 430, 555, 843, -1251, 871, 1550, 105,
  422, 587, 177, -235, -291, -460, 1574, 1653,
  -246, 778, 1159, -147, -777, 1483, -602, 1119,
  -1590, 644, -872, 349, 418, 329, -156, -75,
  817, 1097, 603, 610, 1322, -1285, -1465, 384,
  -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
  -1185, -1530, -1278, 794, -1510, -854, -870, 478,
  -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

/// In-place forward NTT of the polynomial at [off]; input in standard order,
/// output in bit-reversed order with coefficients Barrett-reduced.
///
/// Mirrors `poly_ntt` (poly.c), i.e. `ntt` (ntt.c) followed by `poly_reduce`.
void $ntt(Int16List r, int off) {
  int len, start, j, k, t, zeta;
  k = 1;
  for (len = 128; len >= 2; len >>= 1) {
    for (start = 0; start < 256; start = j + len) {
      zeta = _zetas[k++];
      for (j = start; j < start + len; j++) {
        t = $fqmul(zeta, r[off + j + len]);
        r[off + j + len] = r[off + j] - t;
        r[off + j] = r[off + j] + t;
      }
    }
  }
  $reduce(r, off, 256);
}

/// In-place inverse NTT of the polynomial at [off], multiplied by the
/// Montgomery factor 2^16; input in bit-reversed order, output in standard
/// order. Mirrors `invntt` (ntt.c); `1441 = 2^32 / 128 mod 3329`.
void $invntt(Int16List r, int off) {
  int len, start, j, k, t, zeta;
  k = 127;
  for (len = 2; len <= 128; len <<= 1) {
    for (start = 0; start < 256; start = j + len) {
      zeta = _zetas[k--];
      for (j = start; j < start + len; j++) {
        t = r[off + j];
        // t + r[off+j+len] never leaves the int16 range by the bounds
        // analysis of the reference implementation.
        r[off + j] = $barrett(t + r[off + j + len]);
        r[off + j + len] = $fqmul(zeta, r[off + j + len] - t);
      }
    }
  }
  for (j = 0; j < 256; j++) {
    r[off + j] = $fqmul(r[off + j], 1441);
  }
}

/// Dot product of two vectors of [k] polynomials in the NTT domain:
/// `r = sum(a[v] o b[v]) * 2^-16`, Barrett-reduced.
///
/// Fuses `basemul` (ntt.c) with `polyvec_basemul_acc_montgomery`
/// (polyvec.c). The unreduced accumulation stays below `k * 2 * 3329
/// <= 26632`, inside the int16 range, the same bound the C relies on.
void $basemulAcc(
    Int16List r, int ro, Int16List a, int ao, Int16List b, int bo, int k) {
  int v, i, j, zeta, r0, r1, r2, r3, a0, a1, a2, a3, b0, b1, b2, b3;
  for (i = 0; i < 64; ++i) {
    zeta = _zetas[64 + i];
    r0 = r1 = r2 = r3 = 0;
    for (v = 0; v < k; ++v) {
      j = (v << 8) + (i << 2);
      a0 = a[ao + j];
      a1 = a[ao + j + 1];
      a2 = a[ao + j + 2];
      a3 = a[ao + j + 3];
      b0 = b[bo + j];
      b1 = b[bo + j + 1];
      b2 = b[bo + j + 2];
      b3 = b[bo + j + 3];
      r0 += $fqmul($fqmul(a1, b1), zeta) + $fqmul(a0, b0);
      r1 += $fqmul(a0, b1) + $fqmul(a1, b0);
      r2 += $fqmul($fqmul(a3, b3), -zeta) + $fqmul(a2, b2);
      r3 += $fqmul(a2, b3) + $fqmul(a3, b2);
    }
    j = ro + (i << 2);
    r[j] = $barrett(r0);
    r[j + 1] = $barrett(r1);
    r[j + 2] = $barrett(r2);
    r[j + 3] = $barrett(r3);
  }
}

/// Converts the polynomial at [off] to the Montgomery domain in place.
/// Mirrors `poly_tomont` (poly.c); `1353 = 2^32 mod 3329`.
void $toMont(Int16List r, int off) {
  int i;
  for (i = 0; i < 256; ++i) {
    r[off + i] = $fqmul(r[off + i], 1353);
  }
}

/// Applies Barrett reduction to [n] coefficients starting at [off].
void $reduce(Int16List r, int off, int n) {
  int i;
  for (i = 0; i < n; ++i) {
    r[off + i] = $barrett(r[off + i]);
  }
}

/// Adds [n] coefficients of `a` into `r` without modular reduction.
void $add(Int16List r, int ro, Int16List a, int ao, int n) {
  int i;
  for (i = 0; i < n; ++i) {
    r[ro + i] += a[ao + i];
  }
}

/// Replaces [n] coefficients of `r` with `a - r`, without modular reduction.
void $subFrom(Int16List r, int ro, Int16List a, int ao, int n) {
  int i;
  for (i = 0; i < n; ++i) {
    r[ro + i] = a[ao + i] - r[ro + i];
  }
}

/// Samples a polynomial at [off] from the centered binomial distribution
/// with parameter [eta] (2 or 3), reading `64 * eta` bytes of [buf].
///
/// Ported from `cbd2`/`cbd3` (cbd.c). After the 32-bit little-endian load
/// only `>>>` and `&` touch the word: the load can set bit 31, which an
/// arithmetic shift would smear under dart2js.
void $cbd(Int16List r, int off, Uint8List buf, int eta) {
  int i, j, t, d, p;
  if (eta == 3) {
    for (i = 0; i < 64; ++i) {
      p = 3 * i;
      t = buf[p] | (buf[p + 1] << 8) | (buf[p + 2] << 16);
      d = (t & 0x249249) + ((t >>> 1) & 0x249249) + ((t >>> 2) & 0x249249);
      p = off + (i << 2);
      for (j = 0; j < 24; j += 6) {
        r[p++] = ((d >>> j) & 7) - ((d >>> (j + 3)) & 7);
      }
    }
  } else {
    for (i = 0; i < 32; ++i) {
      p = i << 2;
      t = buf[p] | (buf[p + 1] << 8) | (buf[p + 2] << 16) | (buf[p + 3] << 24);
      d = (t & 0x55555555) + ((t >>> 1) & 0x55555555);
      p = off + (i << 3);
      for (j = 0; j < 32; j += 4) {
        r[p++] = ((d >>> j) & 3) - ((d >>> (j + 2)) & 3);
      }
    }
  }
}

/// Rejection sampling of uniform coefficients mod 3329 from [buflen] bytes
/// of [buf], filling the polynomial at [off] starting at coefficient [ctr].
///
/// Returns the new coefficient count (at most 256). Ported from
/// `rej_uniform` (indcpa.c).
int $rejUniform(Int16List r, int off, int ctr, Uint8List buf, int buflen) {
  int pos = 0, val0, val1;
  while (ctr < 256 && pos + 3 <= buflen) {
    val0 = (buf[pos] | (buf[pos + 1] << 8)) & 0xFFF;
    val1 = ((buf[pos + 1] >> 4) | (buf[pos + 2] << 4)) & 0xFFF;
    pos += 3;
    if (val0 < 3329) {
      r[off + ctr++] = val0;
    }
    if (ctr < 256 && val1 < 3329) {
      r[off + ctr++] = val1;
    }
  }
  return ctr;
}

/// Serializes the polynomial at [ao] into 384 bytes at [ro].
/// Ported from `poly_tobytes` (poly.c); expects Barrett-reduced input.
void $polyToBytes(Uint8List r, int ro, Int16List a, int ao) {
  int i, t0, t1;
  for (i = 0; i < 128; ++i) {
    // map to positive standard representatives; the Uint8List stores
    // truncate to the low 8 bits exactly like the C uint8_t casts
    t0 = a[ao + 2 * i];
    t0 += (t0 >> 15) & 3329;
    t1 = a[ao + 2 * i + 1];
    t1 += (t1 >> 15) & 3329;
    r[ro + 3 * i] = t0;
    r[ro + 3 * i + 1] = (t0 >> 8) | (t1 << 4);
    r[ro + 3 * i + 2] = t1 >> 4;
  }
}

/// Deserializes 384 bytes at [ao] into the polynomial at [ro];
/// inverse of [$polyToBytes]. Ported from `poly_frombytes` (poly.c).
void $polyFromBytes(Int16List r, int ro, Uint8List a, int ao) {
  int i, p;
  for (i = 0; i < 128; ++i) {
    p = ao + 3 * i;
    r[ro + 2 * i] = (a[p] | (a[p + 1] << 8)) & 0xFFF;
    r[ro + 2 * i + 1] = ((a[p + 1] >> 4) | (a[p + 2] << 4)) & 0xFFF;
  }
}

/// Converts a 32-byte message at [mo] to the polynomial at [off].
///
/// Ported from `poly_frommsg` (poly.c); the branch-free mask select
/// `(-bit) & 1665` replaces `cmov_int16`, message bits are secret during
/// decapsulation re-encryption. `1665 = (3329 + 1) / 2`.
void $polyFromMsg(Int16List r, int off, Uint8List msg, int mo) {
  int i, j, m;
  for (i = 0; i < 32; ++i) {
    m = msg[mo + i];
    for (j = 0; j < 8; ++j) {
      r[off + (i << 3) + j] = (-((m >> j) & 1)) & 1665;
    }
  }
}

/// Converts the polynomial at [off] to a 32-byte message at [mo].
///
/// Ported from `poly_tomsg` (poly.c). The signed product stays within
/// 32 bits, and `(x >> 28) & 1` extracts bit 28 of the two's-complement
/// pattern. The same bit the C extracts from its uint32-wrapped value,
/// so the expression is correct on both the VM and dart2js.
void $polyToMsg(Uint8List msg, int mo, Int16List a, int off) {
  int i, j, t, m;
  for (i = 0; i < 32; ++i) {
    m = 0;
    for (j = 0; j < 8; ++j) {
      t = a[off + (i << 3) + j];
      t = (((t << 1) + 1665) * 80635 >> 28) & 1;
      m |= t << j;
    }
    msg[mo + i] = m;
  }
}

/// Compresses the polynomial at [ao] to 4 bits per coefficient, writing
/// 128 bytes at [ro].
///
/// Ported from `poly_compress` (poly.c), 128-byte variant. The product can
/// exceed 32 bits; the exact value (VM) and the ToInt32-wrapped value
/// (dart2js) agree on bits 28..31, which is all `>> 28 & 0xF` reads,
/// matching the deliberate uint32 wraparound of the C code.
void $polyCompress4(Uint8List r, int ro, Int16List a, int ao) {
  int i, u, t0, t1;
  for (i = 0; i < 128; ++i) {
    u = a[ao + 2 * i];
    u += (u >> 15) & 3329;
    t0 = (((u << 4) + 1665) * 80635 >> 28) & 0xF;
    u = a[ao + 2 * i + 1];
    u += (u >> 15) & 3329;
    t1 = (((u << 4) + 1665) * 80635 >> 28) & 0xF;
    r[ro + i] = t0 | (t1 << 4);
  }
}

/// Compresses the polynomial at [ao] to 5 bits per coefficient, writing
/// 160 bytes at [ro]. Ported from `poly_compress` (poly.c), 160-byte
/// variant; same wraparound argument as [$polyCompress4] for `>> 27 & 0x1F`.
void $polyCompress5(Uint8List r, int ro, Int16List a, int ao) {
  int i, j, u, p;
  final t = Uint8List(8);
  for (i = 0; i < 32; ++i) {
    p = ao + (i << 3);
    for (j = 0; j < 8; ++j) {
      u = a[p + j];
      u += (u >> 15) & 3329;
      t[j] = (((u << 5) + 1664) * 40318 >> 27) & 0x1F;
    }
    p = ro + 5 * i;
    r[p] = t[0] | (t[1] << 5);
    r[p + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
    r[p + 2] = (t[3] >> 1) | (t[4] << 4);
    r[p + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
    r[p + 4] = (t[6] >> 2) | (t[7] << 3);
  }
}

/// Decompresses 128 bytes at [ao] into the polynomial at [ro];
/// approximate inverse of [$polyCompress4]. Ported from `poly_decompress`.
void $polyDecompress4(Int16List r, int ro, Uint8List a, int ao) {
  int i, b;
  for (i = 0; i < 128; ++i) {
    b = a[ao + i];
    r[ro + 2 * i] = ((b & 15) * 3329 + 8) >> 4;
    r[ro + 2 * i + 1] = ((b >> 4) * 3329 + 8) >> 4;
  }
}

/// Decompresses 160 bytes at [ao] into the polynomial at [ro];
/// approximate inverse of [$polyCompress5]. Ported from `poly_decompress`.
void $polyDecompress5(Int16List r, int ro, Uint8List a, int ao) {
  int i, j, p;
  final t = Uint8List(8);
  for (i = 0; i < 32; ++i) {
    p = ao + 5 * i;
    t[0] = a[p];
    t[1] = (a[p] >> 5) | (a[p + 1] << 3);
    t[2] = a[p + 1] >> 2;
    t[3] = (a[p + 1] >> 7) | (a[p + 2] << 1);
    t[4] = (a[p + 2] >> 4) | (a[p + 3] << 4);
    t[5] = a[p + 3] >> 1;
    t[6] = (a[p + 3] >> 6) | (a[p + 4] << 2);
    t[7] = a[p + 4] >> 3;
    p = ro + (i << 3);
    for (j = 0; j < 8; ++j) {
      r[p + j] = ((t[j] & 31) * 3329 + 16) >> 5;
    }
  }
}

/// Compresses a vector of [k] polynomials to 10 bits per coefficient,
/// writing `320 * k` bytes at [ro]. Ported from `polyvec_compress`
/// (polyvec.c); the wide division step lives in the platform twin.
void $vecCompress10(Uint8List r, int ro, Int16List a, int k) {
  int i, u, t0, t1, t2, t3, p;
  p = ro;
  for (i = 0; i < (k << 8); i += 4) {
    u = a[i];
    u += (u >> 15) & 3329;
    t0 = $compress10(u);
    u = a[i + 1];
    u += (u >> 15) & 3329;
    t1 = $compress10(u);
    u = a[i + 2];
    u += (u >> 15) & 3329;
    t2 = $compress10(u);
    u = a[i + 3];
    u += (u >> 15) & 3329;
    t3 = $compress10(u);
    r[p] = t0;
    r[p + 1] = (t0 >> 8) | (t1 << 2);
    r[p + 2] = (t1 >> 6) | (t2 << 4);
    r[p + 3] = (t2 >> 4) | (t3 << 6);
    r[p + 4] = t3 >> 2;
    p += 5;
  }
}

/// Compresses a vector of [k] polynomials to 11 bits per coefficient,
/// writing `352 * k` bytes at [ro]. Ported from `polyvec_compress`
/// (polyvec.c); the wide division step lives in the platform twin.
void $vecCompress11(Uint8List r, int ro, Int16List a, int k) {
  int i, j, u, p;
  final t = Uint16List(8);
  p = ro;
  for (i = 0; i < (k << 8); i += 8) {
    for (j = 0; j < 8; ++j) {
      u = a[i + j];
      u += (u >> 15) & 3329;
      t[j] = $compress11(u);
    }
    r[p] = t[0];
    r[p + 1] = (t[0] >> 8) | (t[1] << 3);
    r[p + 2] = (t[1] >> 5) | (t[2] << 6);
    r[p + 3] = t[2] >> 2;
    r[p + 4] = (t[2] >> 10) | (t[3] << 1);
    r[p + 5] = (t[3] >> 7) | (t[4] << 4);
    r[p + 6] = (t[4] >> 4) | (t[5] << 7);
    r[p + 7] = t[5] >> 1;
    r[p + 8] = (t[5] >> 9) | (t[6] << 2);
    r[p + 9] = (t[6] >> 6) | (t[7] << 5);
    r[p + 10] = t[7] >> 3;
    p += 11;
  }
}

/// Decompresses `320 * k` bytes at [ao] into a vector of [k] polynomials;
/// approximate inverse of [$vecCompress10]. Ported from
/// `polyvec_decompress` (polyvec.c).
void $vecDecompress10(Int16List r, Uint8List a, int ao, int k) {
  int i, t0, t1, t2, t3, p;
  p = ao;
  for (i = 0; i < (k << 8); i += 4) {
    t0 = a[p] | (a[p + 1] << 8);
    t1 = (a[p + 1] >> 2) | (a[p + 2] << 6);
    t2 = (a[p + 2] >> 4) | (a[p + 3] << 4);
    t3 = (a[p + 3] >> 6) | (a[p + 4] << 2);
    p += 5;
    r[i] = ((t0 & 0x3FF) * 3329 + 512) >> 10;
    r[i + 1] = ((t1 & 0x3FF) * 3329 + 512) >> 10;
    r[i + 2] = ((t2 & 0x3FF) * 3329 + 512) >> 10;
    r[i + 3] = ((t3 & 0x3FF) * 3329 + 512) >> 10;
  }
}

/// Decompresses `352 * k` bytes at [ao] into a vector of [k] polynomials;
/// approximate inverse of [$vecCompress11]. Ported from
/// `polyvec_decompress` (polyvec.c).
void $vecDecompress11(Int16List r, Uint8List a, int ao, int k) {
  int i, j, p;
  final t = Uint16List(8);
  p = ao;
  for (i = 0; i < (k << 8); i += 8) {
    t[0] = a[p] | (a[p + 1] << 8);
    t[1] = (a[p + 1] >> 3) | (a[p + 2] << 5);
    t[2] = (a[p + 2] >> 6) | (a[p + 3] << 2) | (a[p + 4] << 10);
    t[3] = (a[p + 4] >> 1) | (a[p + 5] << 7);
    t[4] = (a[p + 5] >> 4) | (a[p + 6] << 4);
    t[5] = (a[p + 6] >> 7) | (a[p + 7] << 1) | (a[p + 8] << 9);
    t[6] = (a[p + 8] >> 2) | (a[p + 9] << 6);
    t[7] = (a[p + 9] >> 5) | (a[p + 10] << 3);
    p += 11;
    for (j = 0; j < 8; ++j) {
      r[i + j] = ((t[j] & 0x7FF) * 3329 + 1024) >> 11;
    }
  }
}
