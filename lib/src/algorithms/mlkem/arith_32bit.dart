// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

// JS-safe mirror of `arith_64bit.dart`, used when compiling for the web where
// `int` is an IEEE-754 double (exact up to 2^53) and all bitwise shifts are
// 32-bit operations. Any change here needs the equivalent change there.

// dart2js pitfall this file is built around: `>>` on a NEGATIVE receiver may
// return the unsigned 32-bit reinterpretation of the result depending on
// call-site inference. No expression here shifts a possibly-negative value.

/// Montgomery reduction: given `a` with |a| < 3329 * 2^15, returns a value
/// congruent to `a * 2^-16 mod 3329` in (-3329, 3329).
///
/// `|a * -3327|` stays below 2^39, exact in a double; the low 16 bits are
/// sign-extended with the xor trick because 64-bit shifts are unavailable
/// under dart2js. `a - t * 3329` is exactly divisible by 2^16 by the
/// Montgomery construction, so `~/` equals the arithmetic shift without
/// shifting a negative value.
@pragma('dart2js:tryInline')
int $montgomeryReduce(int a) {
  int t = (a * -3327) & 0xFFFF;
  t = (t ^ 0x8000) - 0x8000;
  return (a - t * 3329) ~/ 65536;
}

/// Barrett reduction: for |a| <= 65534, returns the centered representative
/// congruent to `a mod 3329` in [-1664, 1664].
///
/// `20159 = round(2^26 / 3329)`. The bias `2^31` (a multiple of 2^26,
/// removed again as 32 after the division) keeps the numerator positive, so
/// the floor division is portable; it stays below 2^32, exact in a double.
@pragma('dart2js:tryInline')
int $barrett(int a) {
  int t = (20159 * a + 2181038080) ~/ 67108864 - 32;
  return a - t * 3329;
}

/// Multiplication followed by Montgomery reduction: `a * b * 2^-16 mod 3329`
@pragma('dart2js:tryInline')
int $fqmul(int a, int b) => $montgomeryReduce(a * b);

/// The division-free 10-bit compression step: `round(u * 2^10 / 3329) & 0x3FF`
/// for `u` in `[0, 3329)`. The product stays below 2^43, exact in a double,
/// but too wide for a dart2js shift, hence the division by 2^32.
@pragma('dart2js:tryInline')
int $compress10(int u) => (((u << 10) + 1665) * 1290167 ~/ 0x100000000) & 0x3FF;

/// The division-free 11-bit compression step: `round(u * 2^11 / 3329) & 0x7FF`
/// for `u` in `[0, 3329)`.
@pragma('dart2js:tryInline')
int $compress11(int u) => (((u << 11) + 1664) * 645084 ~/ 0x80000000) & 0x7FF;

/// Compares `len` bytes of [a] and [b] in constant time.
///
/// Returns 0 if they are equal, 1 otherwise. The full-length loop never exits
/// early and the final mask avoids a branch; `r | -r` sets bit 31 whenever
/// `r` is non-zero, which is portable for `r` in `[0, 255]`.
int $verify(Uint8List a, Uint8List b, int len) {
  int i, r = 0;
  for (i = 0; i < len; i++) {
    r |= a[i] ^ b[i];
  }
  return ((r | -r) >> 31) & 1;
}
