// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import "dart:io";
import 'dart:math';

import 'base.dart';
import 'chacha20.dart' as chacha20;
import 'chacha20_poly1305.dart' as chacha20poly1305;
import 'salsa20.dart' as salsa20;
import 'salsa20_poly1305.dart' as salsa20poly1305;
import 'xor.dart' as xor;
import 'aes128.dart' as aes128;

IOSink sink = stdout;
RandomAccessFile? raf;

void dump(message) {
  raf?.writeStringSync(message + '\n');
  stdout.writeln(message);
}

// ---------------------------------------------------------------------
// Symmetric Cipher benchmarks
// ---------------------------------------------------------------------
void measureSymmetricCiphers() {
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
      "AES-128": [
        aes128.CipherlibBenchmark(size, iter),
      ],
      "ChaCha20": [
        chacha20.CipherlibBenchmark(size, iter),
        chacha20.PointyCastleBenchmark(size, iter),
      ],
      "ChaCha20/Poly1305": [
        chacha20poly1305.CipherlibBenchmark(size, iter),
        chacha20poly1305.CryptographyBenchmark(size, iter),
      ],
      "ChaCha20/Poly1305(digest)": [
        chacha20poly1305.CipherlibDigestBenchmark(size, iter),
      ],
      "Salsa20": [
        salsa20.CipherlibBenchmark(size, iter),
        salsa20.PointyCastleBenchmark(size, iter),
      ],
      "Salsa20/Poly1305": [
        salsa20poly1305.CipherlibBenchmark(size, iter),
      ],
      "Salsa20/Poly1305(digest)": [
        salsa20poly1305.CipherlibDigestBenchmark(size, iter),
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
        var runtime = benchmark.measure();
        var hashRate = 1e6 * iter * size / runtime;
        diff[benchmark.name] = runtime;
        rate[benchmark.name] = '${formatSize(hashRate)}/s';
      }
      var me = entry.value.first;
      var mine = diff[me.name]!;
      var best = diff.values.fold(mine, min);

      var message = '| ${entry.key}     ';
      for (var name in names) {
        message += " | ";
        if (!diff.containsKey(name)) {
          message += "    \u2796    ";
          continue;
        }
        var value = diff[name]!;
        if (value == best) {
          message += '**${rate[name]}**';
        } else {
          message += '${rate[name]}';
        }
        if (value > mine) {
          var p = (100 * (value - mine) / mine).round();
          if (p > 0) {
            message += ' <br> `$p% slower`';
          }
        } else if (value < mine) {
          var p = (100 * (mine - value) / mine).round();
          if (p > 0) {
            message += ' <br> `$p% faster`';
          }
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

  measureSymmetricCiphers();

  var ram = '3200MHz';
  var processor = 'AMD Ryzen 7 5800X';
  dump('> All benchmarks are done on _${processor}_ processor '
      'and _${ram}_ RAM using compiled _exe_');

  raf?.flushSync();
  raf?.closeSync();
}
