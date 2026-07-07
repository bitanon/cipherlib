// The Blowfish P-box and S-box initial values are the hexadecimal digits of
// the fractional part of PI, per the specification:
// https://www.schneier.com/academic/blowfish/

import 'dart:io';
import 'dart:typed_data';

/// MDS matrix primitive polynomial: `x^8 + x^6 + x^5 + x^3 + 1`
const int _mdsPoly = 0x169;

/// Builds a 256-byte permutation from four 4-bit permutation tables
Uint8List _buildQ(
  List<int> t0,
  List<int> t1,
  List<int> t2,
  List<int> t3,
) {
  int x, a, b, a1, b1, a2, b2, a3, b3;
  final q = Uint8List(256);
  for (x = 0; x < 256; ++x) {
    a = x >>> 4;
    b = x & 15;
    a1 = a ^ b;
    b1 = (a ^ ((b >>> 1) | ((b & 1) << 3)) ^ ((a & 1) << 3)) & 15;
    a2 = t0[a1];
    b2 = t1[b1];
    a3 = a2 ^ b2;
    b3 = (a2 ^ ((b2 >>> 1) | ((b2 & 1) << 3)) ^ ((a2 & 1) << 3)) & 15;
    q[x] = (t3[b3] << 4) | t2[a3];
  }
  return q;
}

/// Returns `a * b` in **GF(`2^8`)** with the primitive polynomial [p]
int _gfMult(int a, int b, int p) {
  int i, result = 0;
  for (i = 0; i < 8; ++i) {
    if (a & 1 != 0) {
      result ^= b;
    }
    a >>>= 1;
    b <<= 1;
    if (b & 0x100 != 0) {
      b ^= p;
    }
  }
  return result & 0xFF;
}

/// Builds the contribution of every byte at column [col] of the MDS
/// matrix multiplication, packed as little-endian 32-bit words.
Uint32List _buildMDSColumn(int col) {
  int x, m1, m5B, mEF;
  final t = Uint32List(256);
  for (x = 0; x < 256; ++x) {
    m1 = x;
    m5B = _gfMult(x, 0x5B, _mdsPoly);
    mEF = _gfMult(x, 0xEF, _mdsPoly);
    switch (col) {
      case 0:
        t[x] = m1 | (m5B << 8) | (mEF << 16) | (mEF << 24);
        break;
      case 1:
        t[x] = mEF | (mEF << 8) | (m5B << 16) | (m1 << 24);
        break;
      case 2:
        t[x] = m5B | (mEF << 8) | (m1 << 16) | (mEF << 24);
        break;
      default:
        t[x] = m5B | (m1 << 8) | (mEF << 16) | (m5B << 24);
    }
  }
  return t;
}

/// The fixed permutation q0, built from the 4-bit tables of the spec
Uint8List q0 = _buildQ(
  const [
    0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, //
    0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4,
  ],
  const [
    0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, //
    0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD,
  ],
  const [
    0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, //
    0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1,
  ],
  const [
    0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, //
    0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA,
  ],
);

/// The fixed permutation q1, built from the 4-bit tables of the spec
Uint8List q1 = _buildQ(
  const [
    0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, //
    0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5,
  ],
  const [
    0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, //
    0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8,
  ],
  const [
    0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, //
    0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF,
  ],
  const [
    0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, //
    0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA,
  ],
);

/// MDS matrix column 0 contributions packed as little-endian words
Uint32List mds0 = _buildMDSColumn(0);

/// MDS matrix column 1 contributions packed as little-endian words
Uint32List mds1 = _buildMDSColumn(1);

/// MDS matrix column 2 contributions packed as little-endian words
Uint32List mds2 = _buildMDSColumn(2);

/// MDS matrix column 3 contributions packed as little-endian words
Uint32List mds3 = _buildMDSColumn(3);

void main() {
  // -------------------------------------------------------------------
  // _q0
  // -------------------------------------------------------------------
  stdout.writeln(
      '/// The fixed permutation q0, built from the 4-bit tables of the spec');
  stdout.writeln('const _q0 = <int>[');
  final line = StringBuffer();
  for (int x in q0) {
    final hex = x.toRadixString(16).padLeft(8, '0').toUpperCase();
    line.write(' 0x$hex,');
    if (line.length + 2 > 66) {
      stdout.writeln(' ${line.toString()}');
      line.clear();
    }
  }
  if (line.isNotEmpty) {
    stdout.writeln(' ${line.toString()}');
  }
  stdout.writeln('];');
  stdout.writeln('');

  // -------------------------------------------------------------------
  // _q1
  // -------------------------------------------------------------------
  stdout.writeln(
      '/// The fixed permutation q1, built from the 4-bit tables of the spec');
  stdout.writeln('const _q1 = <int>[');
  line.clear();
  for (int x in q1) {
    final hex = x.toRadixString(16).padLeft(8, '0').toUpperCase();
    line.write(' 0x$hex,');
    if (line.length + 2 > 66) {
      stdout.writeln(' ${line.toString()}');
      line.clear();
    }
  }
  if (line.isNotEmpty) {
    stdout.writeln(' ${line.toString()}');
  }
  stdout.writeln('];');

  // -------------------------------------------------------------------
  // _mds0
  // -------------------------------------------------------------------
  stdout.writeln(
      '/// MDS matrix column 0 contributions packed as little-endian words');
  stdout.writeln('const _mds0 = <int>[');
  line.clear();
  for (int x in mds0) {
    final hex = x.toRadixString(16).padLeft(8, '0').toUpperCase();
    line.write(' 0x$hex,');
    if (line.length + 2 > 66) {
      stdout.writeln(' ${line.toString()}');
      line.clear();
    }
  }
  if (line.isNotEmpty) {
    stdout.writeln(' ${line.toString()}');
  }
  stdout.writeln('];');

  // -------------------------------------------------------------------
  // _mds1
  // -------------------------------------------------------------------
  stdout.writeln(
      '/// MDS matrix column 1 contributions packed as little-endian words');
  stdout.writeln('const _mds1 = <int>[');
  line.clear();
  for (int x in mds1) {
    final hex = x.toRadixString(16).padLeft(8, '0').toUpperCase();
    line.write(' 0x$hex,');
    if (line.length + 2 > 66) {
      stdout.writeln(' ${line.toString()}');
      line.clear();
    }
  }
  if (line.isNotEmpty) {
    stdout.writeln(' ${line.toString()}');
  }
  stdout.writeln('];');

  // -------------------------------------------------------------------
  // _mds2
  // -------------------------------------------------------------------
  stdout.writeln(
      '/// MDS matrix column 2 contributions packed as little-endian words');
  stdout.writeln('const _mds2 = <int>[');
  line.clear();
  for (int x in mds2) {
    final hex = x.toRadixString(16).padLeft(8, '0').toUpperCase();
    line.write(' 0x$hex,');
    if (line.length + 2 > 66) {
      stdout.writeln(' ${line.toString()}');
      line.clear();
    }
  }
  if (line.isNotEmpty) {
    stdout.writeln(' ${line.toString()}');
  }
  stdout.writeln('];');
  stdout.writeln('');

  // -------------------------------------------------------------------
  // _mds3
  // -------------------------------------------------------------------
  stdout.writeln(
      '/// MDS matrix column 3 contributions packed as little-endian words');
  stdout.writeln('const _mds3 = <int>[');
  line.clear();
  for (int x in mds3) {
    final hex = x.toRadixString(16).padLeft(8, '0').toUpperCase();
    line.write(' 0x$hex,');
    if (line.length + 2 > 66) {
      stdout.writeln(' ${line.toString()}');
      line.clear();
    }
  }
  if (line.isNotEmpty) {
    stdout.writeln(' ${line.toString()}');
  }
  stdout.writeln('];');
}
