// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

// Platform-sensitive leaf primitives for ML-KEM, optimized for the Dart VM
// where `int` is a native 64-bit integer. The JS-safe mirror of this file is
// `arith_32bit.dart`; any change here needs the equivalent change there.

/// Montgomery reduction: given `a` with |a| < 3329 * 2^15, returns a value
/// congruent to `a * 2^-16 mod 3329` in (-3329, 3329).
///
/// Ported from `montgomery_reduce` (reduce.c) of the reference
/// implementation. `(x << 48) >> 48` sign-extends the low 16 bits, matching
/// the C cast `(int16_t)(a * QINV)`; the shift discards any overflow above
/// bit 15 by design.
@pragma('vm:prefer-inline')
int $montgomeryReduce(int a) {
  int t = ((a * -3327) << 48) >> 48;
  return (a - t * 3329) >> 16;
}

/// Multiplication followed by Montgomery reduction: `a * b * 2^-16 mod 3329`
@pragma('vm:prefer-inline')
int $fqmul(int a, int b) => $montgomeryReduce(a * b);

/// Barrett reduction: for |a| <= 65534, returns the centered representative
/// congruent to `a mod 3329` in [-1664, 1664].
///
/// Ported from `barrett_reduce` (reduce.c); `20159 = round(2^26 / 3329)`.
@pragma('vm:prefer-inline')
int $barrett(int a) {
  int t = (20159 * a + (1 << 25)) >> 26;
  return a - t * 3329;
}

/// The division-free 10-bit compression step: `round(u * 2^10 / 3329) & 0x3FF`
/// for `u` in `[0, 3329)`. The product stays below 2^43, safely inside a
/// 64-bit int. Ported from `polyvec_compress` (polyvec.c).
@pragma('vm:prefer-inline')
int $compress10(int u) => (((u << 10) + 1665) * 1290167 >> 32) & 0x3FF;

/// The division-free 11-bit compression step: `round(u * 2^11 / 3329) & 0x7FF`
/// for `u` in `[0, 3329)`. Ported from `polyvec_compress` (polyvec.c).
@pragma('vm:prefer-inline')
int $compress11(int u) => (((u << 11) + 1664) * 645084 >> 31) & 0x7FF;

/// Compares `len` bytes of [a] and [b] in constant time.
///
/// Returns 0 if they are equal, 1 otherwise. Ported from `verify` (verify.c);
/// the full-length loop never exits early and the final mask avoids a branch.
int $verify(Uint8List a, Uint8List b, int len) {
  int i, r = 0;
  for (i = 0; i < len; i++) {
    r |= a[i] ^ b[i];
  }
  return (-r) >>> 63;
}
