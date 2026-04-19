// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/cipherlib.dart';

import '_base.dart';

/// Runs nonce helper benchmarks; each result line is passed to [emit].
void measureNonce(void Function(String) emit) {}

class NonceRandomBenchmark extends InputBenchmark {
  final int byteLength;

  NonceRandomBenchmark(this.byteLength) : super('Nonce.random($byteLength)', 1);

  @override
  void run() {
    Nonce.random(byteLength);
  }
}

class Nonce64RandomBenchmark extends InputBenchmark {
  Nonce64RandomBenchmark() : super('Nonce64.random()', 1);

  @override
  void run() {
    Nonce64.random();
  }
}

class Nonce128RandomBenchmark extends InputBenchmark {
  Nonce128RandomBenchmark() : super('Nonce128.random()', 1);

  @override
  void run() {
    Nonce128.random();
  }
}

class Nonce128HexBenchmark extends InputBenchmark {
  static const _hex = '0102030405060708090a0b0c0d0e0f10';

  Nonce128HexBenchmark() : super('Nonce128.hex', 1);

  @override
  void run() {
    Nonce128.hex(_hex);
  }
}

class Nonce64Int64Benchmark extends InputBenchmark {
  Nonce64Int64Benchmark() : super('Nonce64.int64', 1);

  @override
  void run() {
    Nonce64.int64(0x0807060504030201);
  }
}

class Nonce128Int64Benchmark extends InputBenchmark {
  Nonce128Int64Benchmark() : super('Nonce128.int64', 1);

  @override
  void run() {
    Nonce128.int64(0x090A0B0C0D0E0F10, 0x0102030405060708);
  }
}

class Nonce128ReverseBenchmark extends InputBenchmark {
  late final Nonce128 n;
  Nonce128ReverseBenchmark() : super('Nonce128.reverse', 16) {
    n = Nonce128.bytes(input);
  }

  @override
  void run() {
    n.reverse();
  }
}

class Nonce128PadLeftBenchmark extends InputBenchmark {
  late final Nonce128 n;
  Nonce128PadLeftBenchmark() : super('Nonce128.padLeft(4)', 1) {
    n = Nonce128.bytes(input);
  }

  @override
  void run() {
    n.padLeft(4);
  }
}

void main() async {
  print('--------- Nonce ----------');
  await NonceRandomBenchmark(12).measureRate();
  await NonceRandomBenchmark(24).measureRate();
  await Nonce64RandomBenchmark().measureRate();
  await Nonce128RandomBenchmark().measureRate();
  await Nonce128HexBenchmark().measureRate();
  await Nonce128Int64Benchmark().measureRate();
  await Nonce64Int64Benchmark().measureRate();
  await Nonce128ReverseBenchmark().measureRate();
  await Nonce128PadLeftBenchmark().measureRate();
  print('');
}
