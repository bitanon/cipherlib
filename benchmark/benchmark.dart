// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import "dart:io";

import '_base.dart';
import 'aes_cbc.dart' as aes_cbc;
import 'aes_cfb.dart' as aes_cfb;
import 'aes_ctr.dart' as aes_ctr;
import 'aes_ecb.dart' as aes_ecb;
import 'aes_gcm.dart' as aes_gcm;
import 'aes_ige.dart' as aes_ige;
import 'aes_ofb.dart' as aes_ofb;
import 'aes_pcbc.dart' as aes_pcbc;
import 'aes_xts.dart' as aes_xts;
import 'chacha20.dart' as chacha20;
import 'xchacha20.dart' as xchacha20;
import 'xchacha20_poly1305.dart' as xchacha20poly1305;
import 'xsalsa20.dart' as xsalsa20;
import 'xsalsa20_poly1305.dart' as xsalsa20poly1305;
import 'chacha20_poly1305.dart' as chacha20poly1305;
import 'salsa20.dart' as salsa20;
import 'salsa20_poly1305.dart' as salsa20poly1305;
import 'xor.dart' as xor;

IOSink sink = stdout;
RandomAccessFile? raf;

void dump(String message) {
  raf?.writeStringSync('$message\n');
  stdout.writeln(message);
}

// ---------------------------------------------------------------------
// Symmetric Cipher benchmarks
// ---------------------------------------------------------------------
Future<void> measureSymmetricCiphers() async {
  /**
   * TODO: Change the layout to something like this:
   * 
   * <table>
   * <tr>
   * <th>Algorithms</th>
   * <th>1MB</th>
   * <th>100KB</th>
   * <th>10KB</th>
   * </tr>
   * <tr>
   * <th>XOR</th>
   * <td>
   *  <ul>
   *    <li>algo1: **8.9 Gbps**</li>
   *    <li>algo2: 8.8 Gbps => 2x slow</li>
   *    <li>algo3: 8.7 Gbps => 3x slow</li>
   *  </ul>
   *  </td>
   * </tr>
   * </table>
   */
  for (int size in [1 << 20, 1 << 10, 1 << 5]) {
    var algorithms = {
      "XOR": [
        xor.CipherlibBenchmark(size),
      ],
      "Salsa20": [
        salsa20.CipherlibBenchmark(size),
        salsa20.PointyCastleBenchmark(size),
      ],
      "Salsa20/Poly1305": [
        salsa20poly1305.CipherlibBenchmark(size),
      ],
      "XSalsa20": [
        xsalsa20.CipherlibBenchmark(size),
      ],
      "XSalsa20/Poly1305": [
        xsalsa20poly1305.CipherlibBenchmark(size),
      ],
      "ChaCha20": [
        chacha20.CipherlibBenchmark(size),
        chacha20.PointyCastleBenchmark(size),
      ],
      "ChaCha20/Poly1305": [
        chacha20poly1305.CipherlibBenchmark(size),
        chacha20poly1305.PointyCastleBenchmark(size),
        chacha20poly1305.CryptographyBenchmark(size),
      ],
      "XChaCha20": [
        xchacha20.CipherlibBenchmark(size),
      ],
      "XChaCha20/Poly1305": [
        xchacha20poly1305.CipherlibBenchmark(size),
      ],
      "AES-128/CBC": [
        aes_cbc.CipherlibBenchmark(size, 16),
        aes_cbc.PointyCastleBenchmark(size, 16),
        aes_cbc.CryptographyBenchmark(size, 16),
      ],
      "AES-192/CBC": [
        aes_cbc.CipherlibBenchmark(size, 24),
        aes_cbc.PointyCastleBenchmark(size, 24),
        aes_cbc.CryptographyBenchmark(size, 24),
      ],
      "AES-256/CBC": [
        aes_cbc.CipherlibBenchmark(size, 32),
        aes_cbc.PointyCastleBenchmark(size, 32),
        aes_cbc.CryptographyBenchmark(size, 32),
      ],
      "AES-128/CFB": [
        aes_cfb.CipherlibBenchmark(size, 16),
        aes_cfb.PointyCastleBenchmark(size, 16),
      ],
      "AES-192/CFB": [
        aes_cfb.CipherlibBenchmark(size, 24),
        aes_cfb.PointyCastleBenchmark(size, 24),
      ],
      "AES-256/CFB": [
        aes_cfb.CipherlibBenchmark(size, 32),
        aes_cfb.PointyCastleBenchmark(size, 32),
      ],
      "AES-128/CTR": [
        aes_ctr.CipherlibBenchmark(size, 16),
        aes_ctr.PointyCastleBenchmark(size, 16),
        aes_ctr.CryptographyBenchmark(size, 16),
      ],
      "AES-192/CTR": [
        aes_ctr.CipherlibBenchmark(size, 24),
        aes_ctr.PointyCastleBenchmark(size, 24),
        aes_ctr.CryptographyBenchmark(size, 24),
      ],
      "AES-256/CTR": [
        aes_ctr.CipherlibBenchmark(size, 32),
        aes_ctr.PointyCastleBenchmark(size, 32),
        aes_ctr.CryptographyBenchmark(size, 32),
      ],
      "AES-128/ECB": [
        aes_ecb.CipherlibBenchmark(size, 16),
        aes_ecb.PointyCastleBenchmark(size, 16),
      ],
      "AES-192/ECB": [
        aes_ecb.CipherlibBenchmark(size, 24),
        aes_ecb.PointyCastleBenchmark(size, 24),
      ],
      "AES-256/ECB": [
        aes_ecb.CipherlibBenchmark(size, 32),
        aes_ecb.PointyCastleBenchmark(size, 32),
      ],
      "AES-128/GCM": [
        aes_gcm.CipherlibBenchmark(size, 16),
        aes_gcm.PointyCastleBenchmark(size, 16),
        aes_gcm.CryptographyBenchmark(size, 16),
      ],
      "AES-192/GCM": [
        aes_gcm.CipherlibBenchmark(size, 24),
        aes_gcm.PointyCastleBenchmark(size, 24),
        aes_gcm.CryptographyBenchmark(size, 24),
      ],
      "AES-256/GCM": [
        aes_gcm.CipherlibBenchmark(size, 32),
        aes_gcm.PointyCastleBenchmark(size, 32),
        aes_gcm.CryptographyBenchmark(size, 32),
      ],
      "AES-128/IGE": [
        aes_ige.CipherlibBenchmark(size, 16),
        aes_ige.PointyCastleBenchmark(size, 16),
      ],
      "AES-192/IGE": [
        aes_ige.CipherlibBenchmark(size, 24),
        aes_ige.PointyCastleBenchmark(size, 24),
      ],
      "AES-256/IGE": [
        aes_ige.CipherlibBenchmark(size, 32),
        aes_ige.PointyCastleBenchmark(size, 32),
      ],
      "AES-128/OFB": [
        aes_ofb.CipherlibBenchmark(size, 16),
        aes_ofb.PointyCastleBenchmark(size, 16),
      ],
      "AES-192/OFB": [
        aes_ofb.CipherlibBenchmark(size, 24),
        aes_ofb.PointyCastleBenchmark(size, 24),
      ],
      "AES-256/OFB": [
        aes_ofb.CipherlibBenchmark(size, 32),
        aes_ofb.PointyCastleBenchmark(size, 32),
      ],
      "AES-128/PCBC": [
        aes_pcbc.CipherlibBenchmark(size, 16),
      ],
      "AES-192/PCBC": [
        aes_pcbc.CipherlibBenchmark(size, 24),
      ],
      "AES-256/PCBC": [
        aes_pcbc.CipherlibBenchmark(size, 32),
      ],
      "AES-128/XTS": [
        aes_xts.CipherlibBenchmark(size, 16),
      ],
      "AES-192/XTS": [
        aes_xts.CipherlibBenchmark(size, 24),
      ],
      "AES-256/XTS": [
        aes_xts.CipherlibBenchmark(size, 32),
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

    dump("With ${formatSize(size)} message:");
    dump('');
    dump('| Algorithms | `${names.join('` | `')}` |');
    dump('|------------|${separator.join('|')}|');

    for (var entry in algorithms.entries) {
      var best = 0.0;
      var diff = <String, Measurement>{};
      for (var benchmark in entry.value.reversed) {
        var result = await measure(benchmark);
        diff[benchmark.name] = result;
        if (result.speed > best) {
          best = result.speed;
        }
      }
      if (diff.isEmpty) continue;
      var mine = diff.values.last.speed;

      var message = '| ${entry.key}     ';
      for (var name in names) {
        message += " | ";
        if (!diff.containsKey(name)) {
          continue;
        }

        var result = diff[name]!;
        if (result.speed == best) {
          message += '**${result.speedString}**';
        } else {
          message += result.speedString;
        }

        if (mine < result.speed) {
          var p = formatDecimal(result.speed / mine);
          message += ' <br> `${p}x fast`';
        } else if (mine > result.speed) {
          var p = formatDecimal(mine / result.speed);
          message += ' <br> `${p}x slow`';
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
