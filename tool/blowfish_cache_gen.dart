// The Blowfish P-box and S-box initial values are the hexadecimal digits of
// the fractional part of PI, per the specification:
// https://www.schneier.com/academic/blowfish/

import 'dart:io';

/// Computes `arccot(x) * unity` using the Taylor series expansion.
BigInt _arccot(int x, BigInt unity) {
  final xsq = BigInt.from(x * x);
  var term = unity ~/ BigInt.from(x);
  var sum = term;
  var n = 1;
  var negative = true;
  while (term.sign != 0) {
    n += 2;
    term = term ~/ xsq;
    if (negative) {
      sum -= term ~/ BigInt.from(n);
    } else {
      sum += term ~/ BigInt.from(n);
    }
    negative = !negative;
  }
  return sum;
}

void main() {
  // 18 + 4 * 256 = 1042 words of 8 hex digits each, plus guard digits
  const words = 1042;
  const guard = 16;
  final unity = BigInt.one << ((8 * words + guard) * 4);

  // Machin formula: PI = 16 * arccot(5) - 4 * arccot(239)
  final pi = (BigInt.from(16) * _arccot(5, unity)) -
      (BigInt.from(4) * _arccot(239, unity));

  // drop the integer part (3) and the guard digits
  final frac = (pi - (BigInt.from(3) * unity)) >> (guard * 4);

  final table = List<int>.generate(
    words,
    (i) => ((frac >> ((words - 1 - i) * 32)) & BigInt.from(0xFFFFFFFF)).toInt(),
  );

  // known values from the reference implementation
  assert(table[0] == 0x243F6A88, 'P[0] mismatch');
  assert(table[17] == 0x8979FB1B, 'P[17] mismatch');
  assert(table[18] == 0xD1310BA6, 'S0[0] mismatch');
  assert(table[1041] == 0x3AC372E6, 'S3[255] mismatch');

  stdout.writeln('// 18 P-box entries followed by 4 x 256 S-box entries');
  stdout.writeln('const _pi = <int>[');
  final line = StringBuffer();
  for (int i = 0; i < words; ++i) {
    final hex = table[i].toRadixString(16).padLeft(8, '0').toUpperCase();
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
