// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import "dart:io";

import 'package:cipherlib/cipherlib.dart';
import 'package:pqcrypto/pqcrypto.dart' as pqc;

import '_base.dart';
import 'aes_cbc.dart' as aes_cbc;
import 'aes_ccm.dart' as aes_ccm;
import 'aes_cfb.dart' as aes_cfb;
import 'aes_ctr.dart' as aes_ctr;
import 'aes_ecb.dart' as aes_ecb;
import 'aes_gcm.dart' as aes_gcm;
import 'aes_ige.dart' as aes_ige;
import 'aes_ofb.dart' as aes_ofb;
import 'aes_pcbc.dart' as aes_pcbc;
import 'aes_xts.dart' as aes_xts;
import 'blowfish_ecb.dart' as blowfish_ecb;
import 'blowfish_cbc.dart' as blowfish_cbc;
import 'blowfish_ctr.dart' as blowfish_ctr;
import 'chacha20.dart' as chacha20;
import 'chacha20_poly1305.dart' as chacha20poly1305;
import 'mlkem.dart' as mlkem;
import 'salsa20.dart' as salsa20;
import 'salsa20_poly1305.dart' as salsa20poly1305;
import 'twofish_ecb.dart' as twofish_ecb;
import 'twofish_cbc.dart' as twofish_cbc;
import 'twofish_ctr.dart' as twofish_ctr;
import 'xchacha20.dart' as xchacha20;
import 'xchacha20_poly1305.dart' as xchacha20poly1305;
import 'xor.dart' as xor;
import 'xsalsa20.dart' as xsalsa20;
import 'xsalsa20_poly1305.dart' as xsalsa20poly1305;

IOSink sink = stdout;
RandomAccessFile? raf;

void dump(String message) {
  raf?.writeStringSync('$message\n');
  stdout.writeln(message);
}

// ---------------------------------------------------------------------
// Symmetric Cipher benchmarks
// ---------------------------------------------------------------------

/// The stream ciphers (and their Poly1305 AEAD variants) for [size].
///
/// In every group cipherlib is listed first, so it is the baseline in a cell.
Map<String, List<Benchmark>> buildStreamCiphers(int size) {
  return {
    "XOR": [
      xor.CipherlibBenchmark(size),
    ],
    "Salsa20": [
      salsa20.CipherlibBenchmark(size),
      salsa20.PointyCastleBenchmark(size),
    ],
    "Salsa20 / Poly1305": [
      salsa20poly1305.CipherlibBenchmark(size),
    ],
    "XSalsa20": [
      xsalsa20.CipherlibBenchmark(size),
    ],
    "XSalsa20 / Poly1305": [
      xsalsa20poly1305.CipherlibBenchmark(size),
    ],
    "ChaCha20": [
      chacha20.CipherlibBenchmark(size),
      chacha20.PointyCastleBenchmark(size),
    ],
    "ChaCha20 / Poly1305": [
      chacha20poly1305.CipherlibBenchmark(size),
      chacha20poly1305.CryptographyBenchmark(size),
      chacha20poly1305.PointyCastleBenchmark(size),
    ],
    "XChaCha20": [
      xchacha20.CipherlibBenchmark(size),
    ],
    "XChaCha20 / Poly1305": [
      xchacha20poly1305.CipherlibBenchmark(size),
    ],
  };
}

/// The AES block-cipher modes for [size].
Map<String, List<Benchmark>> buildAESModes(int size) {
  return {
    "AES-128 / CBC": [
      aes_cbc.CipherlibBenchmark(size, 16),
      aes_cbc.CryptographyBenchmark(size, 16),
      aes_cbc.PointyCastleBenchmark(size, 16),
    ],
    "AES-192 / CBC": [
      aes_cbc.CipherlibBenchmark(size, 24),
      aes_cbc.CryptographyBenchmark(size, 24),
      aes_cbc.PointyCastleBenchmark(size, 24),
    ],
    "AES-256 / CBC": [
      aes_cbc.CipherlibBenchmark(size, 32),
      aes_cbc.CryptographyBenchmark(size, 32),
      aes_cbc.PointyCastleBenchmark(size, 32),
    ],
    "AES-128 / CCM": [
      aes_ccm.CipherlibBenchmark(size, 16),
      aes_ccm.PointyCastleBenchmark(size, 16),
    ],
    "AES-192 / CCM": [
      aes_ccm.CipherlibBenchmark(size, 24),
      aes_ccm.PointyCastleBenchmark(size, 24),
    ],
    "AES-256 / CCM": [
      aes_ccm.CipherlibBenchmark(size, 32),
      aes_ccm.PointyCastleBenchmark(size, 32),
    ],
    "AES-128 / CFB": [
      aes_cfb.CipherlibBenchmark(size, 16),
      aes_cfb.PointyCastleBenchmark(size, 16),
    ],
    "AES-192 / CFB": [
      aes_cfb.CipherlibBenchmark(size, 24),
      aes_cfb.PointyCastleBenchmark(size, 24),
    ],
    "AES-256 / CFB": [
      aes_cfb.CipherlibBenchmark(size, 32),
      aes_cfb.PointyCastleBenchmark(size, 32),
    ],
    "AES-128 / CTR": [
      aes_ctr.CipherlibBenchmark(size, 16),
      aes_ctr.CryptographyBenchmark(size, 16),
      aes_ctr.PointyCastleBenchmark(size, 16),
    ],
    "AES-192 / CTR": [
      aes_ctr.CipherlibBenchmark(size, 24),
      aes_ctr.CryptographyBenchmark(size, 24),
      aes_ctr.PointyCastleBenchmark(size, 24),
    ],
    "AES-256 / CTR": [
      aes_ctr.CipherlibBenchmark(size, 32),
      aes_ctr.CryptographyBenchmark(size, 32),
      aes_ctr.PointyCastleBenchmark(size, 32),
    ],
    "AES-128 / ECB": [
      aes_ecb.CipherlibBenchmark(size, 16),
      aes_ecb.PointyCastleBenchmark(size, 16),
    ],
    "AES-192 / ECB": [
      aes_ecb.CipherlibBenchmark(size, 24),
      aes_ecb.PointyCastleBenchmark(size, 24),
    ],
    "AES-256 / ECB": [
      aes_ecb.CipherlibBenchmark(size, 32),
      aes_ecb.PointyCastleBenchmark(size, 32),
    ],
    "AES-128 / GCM": [
      aes_gcm.CipherlibBenchmark(size, 16),
      aes_gcm.CryptographyBenchmark(size, 16),
      aes_gcm.PointyCastleBenchmark(size, 16),
    ],
    "AES-192 / GCM": [
      aes_gcm.CipherlibBenchmark(size, 24),
      aes_gcm.CryptographyBenchmark(size, 24),
      aes_gcm.PointyCastleBenchmark(size, 24),
    ],
    "AES-256 / GCM": [
      aes_gcm.CipherlibBenchmark(size, 32),
      aes_gcm.CryptographyBenchmark(size, 32),
      aes_gcm.PointyCastleBenchmark(size, 32),
    ],
    "AES-128 / IGE": [
      aes_ige.CipherlibBenchmark(size, 16),
      aes_ige.PointyCastleBenchmark(size, 16),
    ],
    "AES-192 / IGE": [
      aes_ige.CipherlibBenchmark(size, 24),
      aes_ige.PointyCastleBenchmark(size, 24),
    ],
    "AES-256 / IGE": [
      aes_ige.CipherlibBenchmark(size, 32),
      aes_ige.PointyCastleBenchmark(size, 32),
    ],
    "AES-128 / OFB": [
      aes_ofb.CipherlibBenchmark(size, 16),
      aes_ofb.PointyCastleBenchmark(size, 16),
    ],
    "AES-192 / OFB": [
      aes_ofb.CipherlibBenchmark(size, 24),
      aes_ofb.PointyCastleBenchmark(size, 24),
    ],
    "AES-256 / OFB": [
      aes_ofb.CipherlibBenchmark(size, 32),
      aes_ofb.PointyCastleBenchmark(size, 32),
    ],
    "AES-128 / PCBC": [
      aes_pcbc.CipherlibBenchmark(size, 16),
    ],
    "AES-192 / PCBC": [
      aes_pcbc.CipherlibBenchmark(size, 24),
    ],
    "AES-256 / PCBC": [
      aes_pcbc.CipherlibBenchmark(size, 32),
    ],
    "AES-128 / XTS": [
      aes_xts.CipherlibBenchmark(size, 16),
    ],
    "AES-192 / XTS": [
      aes_xts.CipherlibBenchmark(size, 24),
    ],
    "AES-256 / XTS": [
      aes_xts.CipherlibBenchmark(size, 32),
    ],
  };
}

/// The non-AES block ciphers for [size].
Map<String, List<Benchmark>> buildBlockCiphers(int size) {
  return {
    "Twofish-128 / ECB": [
      twofish_ecb.CipherlibBenchmark(size, 16),
      twofish_ecb.PointyCastleBenchmark(size, 16),
    ],
    "Twofish-192 / ECB": [
      twofish_ecb.CipherlibBenchmark(size, 24),
      twofish_ecb.PointyCastleBenchmark(size, 24),
    ],
    "Twofish-256 / ECB": [
      twofish_ecb.CipherlibBenchmark(size, 32),
      twofish_ecb.PointyCastleBenchmark(size, 32),
    ],
    "Twofish-128 / CBC": [
      twofish_cbc.CipherlibBenchmark(size, 16),
      twofish_cbc.PointyCastleBenchmark(size, 16),
    ],
    "Twofish-192 / CBC": [
      twofish_cbc.CipherlibBenchmark(size, 24),
      twofish_cbc.PointyCastleBenchmark(size, 24),
    ],
    "Twofish-256 / CBC": [
      twofish_cbc.CipherlibBenchmark(size, 32),
      twofish_cbc.PointyCastleBenchmark(size, 32),
    ],
    "Twofish-128 / CTR": [
      twofish_ctr.CipherlibBenchmark(size, 16),
      twofish_ctr.PointyCastleBenchmark(size, 16),
    ],
    "Twofish-192 / CTR": [
      twofish_ctr.CipherlibBenchmark(size, 24),
      twofish_ctr.PointyCastleBenchmark(size, 24),
    ],
    "Twofish-256 / CTR": [
      twofish_ctr.CipherlibBenchmark(size, 32),
      twofish_ctr.PointyCastleBenchmark(size, 32),
    ],
    "Blowfish-128 / ECB": [
      blowfish_ecb.CipherlibBenchmark(size, 16),
      blowfish_ecb.PointyCastleBenchmark(size, 16),
    ],
    "Blowfish-256 / ECB": [
      blowfish_ecb.CipherlibBenchmark(size, 32),
      blowfish_ecb.PointyCastleBenchmark(size, 32),
    ],
    "Blowfish-448 / ECB": [
      blowfish_ecb.CipherlibBenchmark(size, 56),
      blowfish_ecb.PointyCastleBenchmark(size, 56),
    ],
    "Blowfish-128 / CBC": [
      blowfish_cbc.CipherlibBenchmark(size, 16),
      blowfish_cbc.PointyCastleBenchmark(size, 16),
    ],
    "Blowfish-256 / CBC": [
      blowfish_cbc.CipherlibBenchmark(size, 32),
      blowfish_cbc.PointyCastleBenchmark(size, 32),
    ],
    "Blowfish-448 / CBC": [
      blowfish_cbc.CipherlibBenchmark(size, 56),
      blowfish_cbc.PointyCastleBenchmark(size, 56),
    ],
    "Blowfish-128 / CTR": [
      blowfish_ctr.CipherlibBenchmark(size, 16),
      blowfish_ctr.PointyCastleBenchmark(size, 16),
    ],
    "Blowfish-256 / CTR": [
      blowfish_ctr.CipherlibBenchmark(size, 32),
      blowfish_ctr.PointyCastleBenchmark(size, 32),
    ],
    "Blowfish-448 / CTR": [
      blowfish_ctr.CipherlibBenchmark(size, 56),
      blowfish_ctr.PointyCastleBenchmark(size, 56),
    ],
  };
}

// Each column is one KEM operation; rows are the levels (cipherlib first).
Map<String, List<Benchmark>> buildPqcGroups(int op) {
  var levels = {
    MLKEM.kem512(): pqc.PqcKem.kyber512,
    MLKEM.kem768(): pqc.PqcKem.kyber768,
    MLKEM.kem1024(): pqc.PqcKem.kyber1024,
  };
  var result = <String, List<Benchmark>>{};
  for (var entry in levels.entries) {
    var kem = entry.key;
    var other = entry.value;
    if (op == 0) {
      result[kem.name] = [
        mlkem.CipherlibKeygenBenchmark(kem),
        mlkem.PqcryptoKeygenBenchmark(other),
      ];
    } else if (op == 1) {
      result[kem.name] = [
        mlkem.CipherlibEncapsBenchmark(kem),
        mlkem.PqcryptoEncapsBenchmark(kem, other),
      ];
    } else {
      result[kem.name] = [
        mlkem.CipherlibDecapsBenchmark(kem),
        mlkem.PqcryptoDecapsBenchmark(kem, other),
      ];
    }
  }
  return result;
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// A fixed-[width] block-character bar for [speed] relative to [best], used to
/// give each benchmark cell a proportional visual next to its number. A nonzero
/// speed always fills at least one block so it stays visible.
String buildBar(double speed, double best, [int width = 16]) {
  var filled = best <= 0 ? 0 : (speed / best * width).round();
  if (filled < 1) filled = 1;
  if (filled > width) filled = width;
  var full = '█' * filled + '░' * (width - filled);
  return '<code>$full</code>';
}

/// Renders one benchmark cell: a proportional bar, the speed, a medal when it
/// is the fastest ([best]) at this size, and for non-[baseline] rows, the speed
/// ratio against cipherlib's [mine].
String formatCell(Measurement result, double best, double mine, bool baseline) {
  var icon = '';

  var speed = result.speedString;
  if (result.speed == best) {
    icon = '&#127775;';
    speed = '<b>$speed</b>';
  }

  var compare = '';
  if (!baseline) {
    if (mine > result.speed) {
      icon = '&#128315;'; // slow
      compare = formatDecimal(mine / result.speed);
    } else if (mine < result.speed) {
      icon = '&#128314;'; // fast
      compare = formatDecimal(result.speed / mine);
    }
    if (compare.isNotEmpty) {
      compare += 'x';
    }
  }

  var line1 = buildBar(result.speed, best);
  var line2 = '<small>$speed $icon$compare</small>'.trim();
  return '$line1 <br> $line2';
}

/// Prints one HTML comparison table. Rows are `(algorithm, library)` pairs -
/// the algorithm name spans its libraries with `rowspan` - with one data column
/// per entry in [columns], built by [build] for that column index. cipherlib is
/// listed first in each row group and is the baseline for the ratios.
Future<void> measureTable(
  List<String> columns,
  Map<String, List<Benchmark>> Function(int column) build,
) async {
  var maps = [for (var i = 0; i < columns.length; i++) build(i)];

  dump('<table>');
  dump('<thead>');
  dump('  <tr>');
  dump('    <th>Algorithm</th>');
  dump('    <th>Library</th>');
  for (final col in columns) {
    dump('    <th>$col</th>');
  }
  dump('  </tr>');
  dump('</thead>');
  dump('<tbody>');

  int bestRuns = 0;
  int totalRuns = 0;
  for (var name in maps.first.keys) {
    // measure every (library, column) and find the fastest library per column
    var results = <List<Measurement>>[];
    var best = <double>[];
    for (var map in maps) {
      var row = <Measurement>[];
      var top = 0.0;
      for (var benchmark in map[name]!) {
        var result = await measure(benchmark);
        row.add(result);
        if (result.speed > top) top = result.speed;
      }
      results.add(row);
      best.add(top);
    }

    // one row per library; the algorithm name spans them via rowspan
    var libraries = maps.first[name]!;
    for (var li = 0; li < libraries.length; li++) {
      dump('  <tr>');
      if (li == 0) {
        var span = libraries.length > 1 ? ' rowspan="${libraries.length}"' : '';
        dump('    <td$span>$name</td>');
      }
      dump('    <td>${libraries[li].name}</td>');
      for (var ci = 0; ci < maps.length; ci++) {
        var mine = results[ci].first.speed;
        var cell = formatCell(results[ci][li], best[ci], mine, li == 0);
        dump('    <td>$cell</td>');
        totalRuns++;
        if (best[ci] == mine) {
          bestRuns++;
        }
      }
      dump('  </tr>');
    }
  }
  dump('</tbody>');
  dump('</table>');
  dump('');
  dump('> This package comes on top $bestRuns out of $totalRuns times.');
}

Future<void> measureSection<T>(
  String title,
  List<T> columns,
  String Function(T column) header,
  Map<String, List<Benchmark>> Function(T column) build,
) async {
  dump('### $title');
  dump('');
  await measureTable(
    [for (var column in columns) header(column)],
    (i) => build(columns[i]),
  );
  dump('');
}

// ---------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------

final messageSizes = [1 << 20, 1 << 10, 1 << 5];
String sizeHeader(int size) => '${formatSize(size)} message';
String pqcHeader(int op) =>
    const ['Key Generation', 'Encapsulation', 'Decapsulation'][op];

void dumpHeaders() {
  dump("## Benchmarks");
  dump('');
  dump("### Libraries");
  dump('');
  dump("- **Cipherlib** : https://pub.dev/packages/cipherlib");
  dump("- **PointyCastle** : https://pub.dev/packages/pointycastle");
  dump("- **Cryptography** : https://pub.dev/packages/cryptography");
  dump("- **PQCrypto** : https://pub.dev/packages/pqcrypto");
  dump('');
}

void main(List<String> args) async {
  if (args.isNotEmpty) {
    try {
      stdout.writeln('Opening output file: ${args[0]}');
      raf = File(args[0]).openSync(mode: FileMode.writeOnly);
    } catch (err) {
      stderr.writeln(err);
    }
    stdout.writeln('----------------------------------------');
  }

  dumpHeaders();
  raf?.flushSync();

  await measureSection(
    'Stream Ciphers',
    messageSizes,
    sizeHeader,
    buildStreamCiphers,
  );
  raf?.flushSync();

  await measureSection(
    'AES',
    messageSizes,
    sizeHeader,
    buildAESModes,
  );
  raf?.flushSync();

  await measureSection(
    'Blowfish & Twofish',
    messageSizes,
    sizeHeader,
    buildBlockCiphers,
  );
  raf?.flushSync();

  await measureSection(
    'Key Encapsulation',
    [0, 1, 2],
    pqcHeader,
    buildPqcGroups,
  );
  raf?.flushSync();

  raf?.closeSync();
}
