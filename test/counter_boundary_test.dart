// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:test/test.dart';

/// Cross-cutting counter checks for every counter-based cipher.
///
/// A block counter that mis-carries produces a keystream that is still
/// perfectly reversible by the same implementation, so round-trips and the
/// size sweeps in `correctness_test.dart` (which top out at 124568 bytes) can
/// not see it. That is how the dart2wasm AES-GCM carry bug in issue #28
/// survived to a release: it only showed up past 1 MiB, and only on a platform
/// the everyday suite did not run.
///
/// The property asserted here is *counter continuity*: block `j` of a run
/// started at counter `C` must equal block `0` of a run started at `C + j`.
/// It holds for every counter mode, needs no external vector, and — because
/// the starting counter is an input — it reaches the 32-bit and 64-bit carries
/// that no achievable message length could ever walk to.

/// A block counter held as two 32-bit halves.
///
/// The interesting boundaries sit at 2^32 and 2^64, and an `int` literal past
/// 2^53 is not exactly representable on the JS platform this suite also runs
/// on. Splitting the value keeps every intermediate small enough to be exact
/// everywhere.
class _Counter {
  final int high;
  final int low;

  const _Counter(this.high, this.low);

  /// This counter advanced by [n], wrapping at [bits].
  _Counter plus(int n, int bits) {
    var l = low + n;
    var h = high;
    if (l > 0xFFFFFFFF) {
      l -= 0x100000000;
      h = (h + 1) & 0xFFFFFFFF;
    }
    return _Counter(bits == 32 ? 0 : h, l);
  }

  @override
  String toString() => '0x'
      '${high.toRadixString(16).padLeft(8, '0')}'
      '${low.toRadixString(16).padLeft(8, '0')}';
}

/// Produces [blocks] blocks of raw keystream starting from counter [c].
typedef _Keystream = Uint8List Function(_Counter c, int blocks);

class _Subject {
  final String name;
  final int blockSize;
  final int counterBits;
  final _Keystream keystream;

  const _Subject(this.name, this.blockSize, this.counterBits, this.keystream);
}

Uint8List _fill(int size, int mul, int add) {
  final out = Uint8List(size);
  for (int i = 0; i < size; ++i) {
    out[i] = (i * mul + add) & 0xFF;
  }
  return out;
}

/// Builds a CTR-mode IV of [size] bytes: a fixed nonce prefix with [c] packed
/// big-endian into the low [counterBits] bits, which is how every CTR
/// implementation here loads its counter block.
Uint8List _ctrIV(int size, int counterBits, _Counter c) {
  final iv = _fill(size, 3, 5);
  final packed = <int>[
    (c.high >>> 24) & 0xFF,
    (c.high >>> 16) & 0xFF,
    (c.high >>> 8) & 0xFF,
    c.high & 0xFF,
    (c.low >>> 24) & 0xFF,
    (c.low >>> 16) & 0xFF,
    (c.low >>> 8) & 0xFF,
    c.low & 0xFF,
  ];
  final n = counterBits >>> 3;
  iv.setRange(size - n, size, packed.sublist(8 - n));
  return iv;
}

/// Counters positioned two blocks below each carry boundary reachable within
/// [bits], so a short run steps over the carry.
List<_Counter> _boundaries(int bits) {
  final out = <_Counter>[
    const _Counter(0, 0x000000FD), // 8-bit carry
    const _Counter(0, 0x0000FFFD), // 16-bit carry
    const _Counter(0, 0x00FFFFFD), // 24-bit carry
    const _Counter(0, 0xFFFFFFFD), // 32-bit carry
  ];
  if (bits > 32) {
    out.addAll(const [
      _Counter(0x00000001, 0xFFFFFFFD), // carry inside the high word
      _Counter(0x0000FFFF, 0xFFFFFFFD), // 48-bit carry
      _Counter(0xFFFFFFFF, 0xFFFFFFFD), // wrap around modulo 2^64
    ]);
  }
  return out;
}

void main() {
  final key32 = _fill(32, 7, 1);
  final key56 = _fill(56, 7, 1);

  final subjects = <_Subject>[
    _Subject(
      'AES-256/CTR-32',
      16,
      32,
      (c, b) =>
          AES(key32).ctr(_ctrIV(16, 32, c), 32).encrypt(Uint8List(b * 16)),
    ),
    _Subject(
      'AES-256/CTR-64',
      16,
      64,
      (c, b) =>
          AES(key32).ctr(_ctrIV(16, 64, c), 64).encrypt(Uint8List(b * 16)),
    ),
    _Subject(
      'Twofish/CTR-64',
      16,
      64,
      (c, b) =>
          Twofish(key32).ctr(_ctrIV(16, 64, c), 64).encrypt(Uint8List(b * 16)),
    ),
    _Subject(
      'Blowfish/CTR-64',
      8,
      64,
      (c, b) =>
          Blowfish(key56).ctr(_ctrIV(8, 64, c), 64).encrypt(Uint8List(b * 8)),
    ),
    _Subject(
      'ChaCha20/32-bit counter',
      64,
      32,
      (c, b) => ChaCha20(key32, _fill(12, 3, 5), Nonce64.int32(c.low))
          .convert(Uint8List(b * 64)),
    ),
    _Subject(
      'ChaCha20/64-bit counter',
      64,
      64,
      (c, b) => ChaCha20(key32, _fill(8, 3, 5), Nonce64.int32(c.low, c.high))
          .convert(Uint8List(b * 64)),
    ),
    _Subject(
      'XChaCha20',
      64,
      64,
      (c, b) => XChaCha20(key32, _fill(24, 3, 5), Nonce64.int32(c.low, c.high))
          .convert(Uint8List(b * 64)),
    ),
    _Subject(
      'Salsa20',
      64,
      64,
      (c, b) => Salsa20(key32, _fill(8, 3, 5), Nonce64.int32(c.low, c.high))
          .convert(Uint8List(b * 64)),
    ),
    _Subject(
      'XSalsa20',
      64,
      64,
      (c, b) => XSalsa20(key32, _fill(24, 3, 5), Nonce64.int32(c.low, c.high))
          .convert(Uint8List(b * 64)),
    ),
  ];

  for (final s in subjects) {
    group(s.name, () {
      test('keystream is continuous across every carry boundary', () {
        const run = 4;
        for (final start in _boundaries(s.counterBits)) {
          final actual = s.keystream(start, run);
          expect(actual.length, equals(run * s.blockSize));
          for (int j = 0; j < run; ++j) {
            expect(
              toHex(actual.sublist(j * s.blockSize, (j + 1) * s.blockSize)),
              equals(toHex(s.keystream(start.plus(j, s.counterBits), 1))),
              reason: '[start: $start, block: $j]',
            );
          }
        }
      });

      test('keystream stays aligned over a 1 MiB message', () {
        const size = 1048576;
        // Positioned so the 16-bit carry lands eight blocks in; the remainder
        // of the message exercises large-index output addressing, which is
        // where the counter and the output offset can drift apart.
        const start = _Counter(0, 0x0000FFF8);
        final blocks = size ~/ s.blockSize;

        final actual = s.keystream(start, blocks);
        expect(actual.length, equals(size));

        for (final j in <int>[0, 7, 8, 9, 15, blocks - 2, blocks - 1]) {
          expect(
            toHex(actual.sublist(j * s.blockSize, (j + 1) * s.blockSize)),
            equals(toHex(s.keystream(start.plus(j, s.counterBits), 1))),
            reason: '[block: $j]',
          );
        }
      });
    });
  }
}
