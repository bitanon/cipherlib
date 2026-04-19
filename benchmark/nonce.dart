// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/cipherlib.dart';

import '_base.dart';

/// Runs nonce helper benchmarks; each result line is passed to [emit].
void measureNonce(void Function(String) emit) {}

class NonceRandomBenchmark extends InputBenchmark {
  final int byteLength;

  NonceRandomBenchmark(this.byteLength, int iter)
      : super('Nonce.random($byteLength)', 1, iter);

  @override
  void run() {
    Nonce.random(byteLength);
  }
}

class Nonce64RandomBenchmark extends InputBenchmark {
  Nonce64RandomBenchmark(int iter) : super('Nonce64.random()', 1, iter);

  @override
  void run() {
    Nonce64.random();
  }
}

class Nonce128RandomBenchmark extends InputBenchmark {
  Nonce128RandomBenchmark(int iter) : super('Nonce128.random()', 1, iter);

  @override
  void run() {
    Nonce128.random();
  }
}

class Nonce128HexBenchmark extends InputBenchmark {
  static const _hex = '0102030405060708090a0b0c0d0e0f10';

  Nonce128HexBenchmark(int iter) : super('Nonce128.hex', 1, iter);

  @override
  void run() {
    Nonce128.hex(_hex);
  }
}

class Nonce64Int64Benchmark extends InputBenchmark {
  Nonce64Int64Benchmark(int iter) : super('Nonce64.int64', 1, iter);

  @override
  void run() {
    Nonce64.int64(0x0807060504030201);
  }
}

class Nonce128Int64Benchmark extends InputBenchmark {
  Nonce128Int64Benchmark(int iter) : super('Nonce128.int64', 1, iter);

  @override
  void run() {
    Nonce128.int64(0x090A0B0C0D0E0F10, 0x0102030405060708);
  }
}

class Nonce128ReverseBenchmark extends InputBenchmark {
  late final Nonce128 n = Nonce128.bytes(input);

  Nonce128ReverseBenchmark(int iter) : super('Nonce128.reverse', 16, iter);

  @override
  void run() {
    n.reverse();
  }
}

class Nonce128PadLeftBenchmark extends InputBenchmark {
  late final Nonce128 n = Nonce128.bytes(input);

  Nonce128PadLeftBenchmark(int iter) : super('Nonce128.padLeft(4)', 1, iter);

  @override
  void run() {
    n.padLeft(4);
  }
}

void main() async {
  print('--------- Nonce ----------');
  const csprngInner = 400;
  const cheapInner = 250000;

  print('---- iterations: $csprngInner (CSPRNG) ----');
  await NonceRandomBenchmark(12, csprngInner).measureRate();
  await NonceRandomBenchmark(24, csprngInner).measureRate();
  await Nonce64RandomBenchmark(csprngInner).measureRate();
  await Nonce128RandomBenchmark(csprngInner).measureRate();

  print('---- iterations: $cheapInner (cheap paths) ----');
  await Nonce128HexBenchmark(cheapInner).measureRate();
  await Nonce64Int64Benchmark(cheapInner).measureRate();
  await Nonce128Int64Benchmark(cheapInner).measureRate();
  await Nonce128ReverseBenchmark(cheapInner).measureRate();
  await Nonce128PadLeftBenchmark(cheapInner).measureRate();
  print('');
}
