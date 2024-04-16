// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:math';

import 'package:benchmark_harness/benchmark_harness.dart';

Random random = Random();

mixin _BenchmarkTools {
  int get size;
  int get iter;
  String get name;

  void $showRate(double runtime) {
    var nbhps = 1e6 * iter / runtime;
    var rate = nbhps * size;
    var rtms = runtime.round() / 1000;
    var speed = '${formatSize(rate)}/s';
    var mark = '${formatSize(size)} x $iter';
    print('$name($mark): $rtms ms => ${nbhps.round()} rounds @ $speed');
  }

  void $showDiff(Map<String, double> diff) {
    var rate = <String, String>{};
    for (var name in diff.keys) {
      var runtime = diff[name]!;
      var hashRate = 1e6 * iter * size / runtime;
      diff[name] = runtime;
      rate[name] = '${formatSize(hashRate)}/s';
    }
    var mine = diff[name]!;
    var best = diff.values.fold(mine, min);
    for (var entry in diff.entries) {
      var message = "${entry.key} : ${rate[entry.key]}";
      var value = diff[entry.key]!;
      if (value == best) {
        message += ' [best]';
      }
      if (value > mine) {
        var p = (100 * (value - mine) / mine).round();
        message += ' ~ $p% slower';
      } else if (value < mine) {
        var p = (100 * (mine - value) / mine).round();
        message += ' ~ $p% faster';
      }
      print(message);
    }
  }
}

abstract class Benchmark extends BenchmarkBase with _BenchmarkTools {
  @override
  final int size;
  @override
  final int iter;
  final List<int> input;

  Stream<int> get inputStream => Stream.fromIterable(input);

  Benchmark(String name, this.size, this.iter)
      : input = List.filled(size, 0x3f),
        super(name);

  @override
  void exercise() {
    for (int i = 0; i < iter; ++i) {
      run();
    }
  }

  void measureRate() {
    $showRate(measure());
  }

  void measureDiff([List<BenchmarkBase> others = const []]) {
    var diff = <String, double>{};
    for (var benchmark in {this, ...others}) {
      diff[benchmark.name] = benchmark.measure();
    }
    $showDiff(diff);
  }
}

abstract class AsyncBenchmark extends AsyncBenchmarkBase with _BenchmarkTools {
  @override
  final int size;
  @override
  final int iter;
  final List<int> input;

  Stream<int> get inputStream => Stream.fromIterable(input);

  AsyncBenchmark(String name, this.size, this.iter)
      : input = List.filled(size, 0x3f),
        super(name);

  @override
  Future<void> exercise() async {
    for (int i = 0; i < iter; ++i) {
      await run();
    }
  }

  Future<void> measureRate() async {
    $showRate(await measure());
  }

  Future<void> measureDiff([List<dynamic> others = const []]) async {
    var diff = <String, double>{};
    for (var benchmark in {this, ...others}) {
      if (benchmark is BenchmarkBase) {
        diff[benchmark.name] = benchmark.measure();
      } else if (benchmark is AsyncBenchmarkBase) {
        diff[benchmark.name] = await benchmark.measure();
      }
    }
    $showDiff(diff);
  }
}

String formatSize(num value) {
  double size = value.toDouble();
  const suffix = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  int i;
  for (i = 0; size >= 1024; i++) {
    size /= 1024;
  }
  var left = size.floor();
  var right = ((size - left) * 100).floorToDouble();
  var deci = (right / 100).toStringAsFixed(2).substring(2);
  return '$left${right > 0 ? '.$deci' : ''}${suffix[i]}';
}
