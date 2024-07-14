// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import "dart:io";
import 'dart:math';

import 'aes_cbc.dart' as aes_cbc;
import 'aes_pcbc.dart' as aes_pcbc;
import 'aes_ecb.dart' as aes_ecb;
import 'aes_cfb.dart' as aes_cfb;
import 'aes_ctr.dart' as aes_ctr;
import 'aes_gcm.dart' as aes_gcm;
import 'aes_ofb.dart' as aes_ofb;
import 'aes_xts.dart' as aes_xts;
import 'aes_keygen.dart' as aes_keygen;
import 'base.dart';
import 'chacha20.dart' as chacha20;
import 'chacha20_poly1305.dart' as chacha20poly1305;
import 'salsa20.dart' as salsa20;
import 'salsa20_poly1305.dart' as salsa20poly1305;
import 'xor.dart' as xor;

IOSink sink = stdout;
RandomAccessFile? raf;

void dump(message) {
  raf?.writeStringSync(message + '\n');
  stdout.writeln(message);
}

// ---------------------------------------------------------------------
// Symmetric Cipher benchmarks
// ---------------------------------------------------------------------
Future<void> measureSymmetricCiphers() async {
  final conditions = [
    [1 << 20, 10],
    [5 << 10, 5000],
    [16, 100000],
  ];
  for (var condition in conditions) {
    var size = condition[0];
    var iter = condition[1];

    var algorithms = {
      "XOR": [
        xor.CipherlibBenchmark(size, iter),
      ],
      "ChaCha20": [
        chacha20.CipherlibBenchmark(size, iter),
        chacha20.PointyCastleBenchmark(size, iter),
      ],
      "ChaCha20/Poly1305": [
        chacha20poly1305.CipherlibBenchmark(size, iter),
        chacha20poly1305.CryptographyBenchmark(size, iter),
        chacha20poly1305.PointyCastleBenchmark(size, iter),
      ],
      "Salsa20": [
        salsa20.CipherlibBenchmark(size, iter),
        salsa20.PointyCastleBenchmark(size, iter),
      ],
      "Salsa20/Poly1305": [
        salsa20poly1305.CipherlibBenchmark(size, iter),
      ],
      "AES-128:keygen": [
        aes_keygen.CipherlibBenchmark(size, iter, 16),
        aes_keygen.PointyCastleBenchmark(size, iter, 16),
        aes_keygen.CryptographyBenchmark(size, iter, 16),
      ],
      "AES-192:keygen": [
        aes_keygen.CipherlibBenchmark(size, iter, 24),
        aes_keygen.PointyCastleBenchmark(size, iter, 24),
        aes_keygen.CryptographyBenchmark(size, iter, 24),
      ],
      "AES-256:keygen": [
        aes_keygen.CipherlibBenchmark(size, iter, 32),
        aes_keygen.PointyCastleBenchmark(size, iter, 32),
        aes_keygen.CryptographyBenchmark(size, iter, 32),
      ],
      "AES-128/ECB": [
        aes_ecb.CipherlibBenchmark(size, iter, 16),
        aes_ecb.PointyCastleBenchmark(size, iter, 16),
      ],
      "AES-192/ECB": [
        aes_ecb.CipherlibBenchmark(size, iter, 24),
        aes_ecb.PointyCastleBenchmark(size, iter, 24),
      ],
      "AES-256/ECB": [
        aes_ecb.CipherlibBenchmark(size, iter, 32),
        aes_ecb.PointyCastleBenchmark(size, iter, 32),
      ],
      "AES-128/CBC": [
        aes_cbc.CipherlibBenchmark(size, iter, 16),
        aes_cbc.PointyCastleBenchmark(size, iter, 16),
        aes_cbc.CryptographyBenchmark(size, iter, 16),
      ],
      "AES-192/CBC": [
        aes_cbc.CipherlibBenchmark(size, iter, 24),
        aes_cbc.PointyCastleBenchmark(size, iter, 24),
        aes_cbc.CryptographyBenchmark(size, iter, 24),
      ],
      "AES-256/CBC": [
        aes_cbc.CipherlibBenchmark(size, iter, 32),
        aes_cbc.PointyCastleBenchmark(size, iter, 32),
        aes_cbc.CryptographyBenchmark(size, iter, 32),
      ],
      "AES-128/CTR": [
        aes_ctr.CipherlibBenchmark(size, iter, 16),
        aes_ctr.PointyCastleBenchmark(size, iter, 16),
        aes_ctr.CryptographyBenchmark(size, iter, 16),
      ],
      "AES-192/CTR": [
        aes_ctr.CipherlibBenchmark(size, iter, 24),
        aes_ctr.PointyCastleBenchmark(size, iter, 24),
        aes_ctr.CryptographyBenchmark(size, iter, 24),
      ],
      "AES-256/CTR": [
        aes_ctr.CipherlibBenchmark(size, iter, 32),
        aes_ctr.PointyCastleBenchmark(size, iter, 32),
        aes_ctr.CryptographyBenchmark(size, iter, 32),
      ],
      "AES-128/GCM": [
        aes_gcm.CipherlibBenchmark(size, iter, 16),
        aes_gcm.PointyCastleBenchmark(size, iter, 16),
        aes_gcm.CryptographyBenchmark(size, iter, 16),
      ],
      "AES-192/GCM": [
        aes_gcm.CipherlibBenchmark(size, iter, 24),
        aes_gcm.PointyCastleBenchmark(size, iter, 24),
        aes_gcm.CryptographyBenchmark(size, iter, 24),
      ],
      "AES-256/GCM": [
        aes_gcm.CipherlibBenchmark(size, iter, 32),
        aes_gcm.PointyCastleBenchmark(size, iter, 32),
        aes_gcm.CryptographyBenchmark(size, iter, 32),
      ],
      "AES-128/CFB": [
        aes_cfb.CipherlibBenchmark(size, iter, 16),
        aes_cfb.PointyCastleBenchmark(size, iter, 16),
      ],
      "AES-192/CFB": [
        aes_cfb.CipherlibBenchmark(size, iter, 24),
        aes_cfb.PointyCastleBenchmark(size, iter, 24),
      ],
      "AES-256/CFB": [
        aes_cfb.CipherlibBenchmark(size, iter, 32),
        aes_cfb.PointyCastleBenchmark(size, iter, 32),
      ],
      "AES-128/OFB": [
        aes_ofb.CipherlibBenchmark(size, iter, 16),
        aes_ofb.PointyCastleBenchmark(size, iter, 16),
      ],
      "AES-192/OFB": [
        aes_ofb.CipherlibBenchmark(size, iter, 24),
        aes_ofb.PointyCastleBenchmark(size, iter, 24),
      ],
      "AES-256/OFB": [
        aes_ofb.CipherlibBenchmark(size, iter, 32),
        aes_ofb.PointyCastleBenchmark(size, iter, 32),
      ],
      "AES-128/XTS": [
        aes_xts.CipherlibBenchmark(size, iter, 16),
      ],
      "AES-192/XTS": [
        aes_xts.CipherlibBenchmark(size, iter, 24),
      ],
      "AES-256/XTS": [
        aes_xts.CipherlibBenchmark(size, iter, 32),
      ],
      "AES-128/PCBC": [
        aes_pcbc.CipherlibBenchmark(size, iter, 16),
      ],
      "AES-192/PCBC": [
        aes_pcbc.CipherlibBenchmark(size, iter, 24),
      ],
      "AES-256/PCBC": [
        aes_pcbc.CipherlibBenchmark(size, iter, 32),
      ],
    };

    var nameFreq = {};
    for (var entry in algorithms.entries) {
      for (var benchmark in entry.value) {
        nameFreq[benchmark.name] ??= 0;
        nameFreq[benchmark.name]++;
      }
    }
    var names = nameFreq.keys.toList();
    names.sort((a, b) => nameFreq[b] - nameFreq[a]);
    var separator = names.map((e) => ('-' * (e.length + 4)));

    dump("With ${formatSize(size)} message ($iter iterations):");
    dump('');
    dump('| Algorithms | `${names.join('` | `')}` |');
    dump('|------------|${separator.join('|')}|');

    for (var entry in algorithms.entries) {
      var diff = <String, double>{};
      var rate = <String, String>{};
      for (var benchmark in entry.value.reversed) {
        double runtime;
        if (benchmark is AsyncBenchmark) {
          runtime = await benchmark.measure();
        } else if (benchmark is Benchmark) {
          runtime = benchmark.measure();
        } else {
          continue;
        }
        var hashRate = 1e6 * iter * size / runtime;
        diff[benchmark.name] = runtime;
        rate[benchmark.name] = formatSpeed(hashRate);
      }
      if (rate.isEmpty) continue;

      var me = entry.value.first;
      var mine = diff[me.name]!;
      var best = diff.values.fold(mine, min);

      var message = '| ${entry.key}     ';
      for (var name in names) {
        message += " | ";
        if (!diff.containsKey(name)) {
          // message += "    \u2796    ";
          continue;
        }
        var value = diff[name]!;
        if (value == best) {
          message += '**${rate[name]}**';
        } else {
          message += '${rate[name]}';
        }
        if (mine < value) {
          var p = formatDecimal(value / mine);
          message += ' <br> `${p}x slow`';
        } else if (mine > value) {
          var p = formatDecimal(mine / value);
          message += ' <br> `${p}x fast`';
        }
      }
      message += " |";
      dump(message);
    }
    dump('');
  }
}

// ---------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------
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

  dump("# Benchmarks");
  dump('');
  dump("Libraries:");
  dump('');
  dump("- **Cipherlib** : https://pub.dev/packages/cipherlib");
  dump("- **PointyCastle** : https://pub.dev/packages/pointycastle");
  dump("- **Cryptography** : https://pub.dev/packages/cryptography");
  dump('');

  await measureSymmetricCiphers();

  raf?.flushSync();
  raf?.closeSync();
}
