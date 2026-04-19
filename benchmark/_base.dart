// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:math';

import 'package:benchmark_harness/benchmark_harness.dart';

Random random = Random();

mixin Benchmark {
  int get size;
  int get iter;
  String get name;

  Future<void> measureRate() {
    return showRate(this);
  }

  Future<void> measureDiff([List<Benchmark> others = const []]) {
    return showDiff([this, ...others]);
  }
}

abstract class SyncBenchmark extends BenchmarkBase with Benchmark {
  SyncBenchmark(super.name, this.size, this.iter);

  @override
  final int size;

  @override
  final int iter;

  @override
  void exercise() {
    for (int i = 0; i < iter; ++i) {
      run();
    }
  }
}

abstract class AsyncBenchmark extends AsyncBenchmarkBase with Benchmark {
  AsyncBenchmark(super.name, this.size, this.iter);

  @override
  final int size;

  @override
  final int iter;

  @override
  Future<void> exercise() async {
    for (int i = 0; i < iter; ++i) {
      await run();
    }
  }
}

abstract class InputBenchmark extends SyncBenchmark {
  final List<int> input;

  Stream<int> get inputStream => Stream.fromIterable(input);

  InputBenchmark(
    super.name,
    super.size,
    super.iter,
  ) : input = List.filled(size, 0x3f);
}

abstract class AsyncInputBenchmark extends AsyncBenchmark {
  final List<int> input;

  Stream<int> get inputStream => Stream.fromIterable(input);

  AsyncInputBenchmark(
    super.name,
    super.size,
    super.iter,
  ) : input = List.filled(size, 0x3f);
}

/// ------------ Helper Functions ------------

String formatDecimal(double value, [int precision = 2]) {
  var res = value.toStringAsFixed(precision);
  if (precision == 0) {
    return res;
  }
  int p = res.length - 1;
  while (res[p] == '0') {
    p--;
  }
  if (res[p] == '.') {
    p--;
  }
  return res.substring(0, p + 1);
}

String formatSize(num value) {
  int i;
  double size = value.toDouble();
  const suffix = [
    'B',
    'KB',
    'MB',
    'GB',
    'TB',
    'PB',
    'EB',
    'ZB',
    'YB',
  ];
  for (i = 0; size >= 1024; i++) {
    size /= 1024;
  }
  return '${formatDecimal(size)}${suffix[i]}';
}

String formatSpeed(num value) {
  int i;
  double size = (value * 8).toDouble();
  const suffix = [
    '',
    ' kbps',
    ' Mbps',
    ' Gbps',
    ' Tbps',
    ' Pbps',
    ' Ebps',
    ' Zbps',
    ' Ybps',
  ];
  size /= 1000;
  for (i = 1; size >= 1000; i++) {
    size /= 1000;
  }
  if (size >= 100) {
    size = size.roundToDouble();
  }
  return '${formatDecimal(size)}${suffix[i]}';
}

Future<double> measure(Benchmark benchmark) async {
  if (benchmark is SyncBenchmark) {
    return benchmark.measure();
  } else if (benchmark is AsyncBenchmark) {
    return await benchmark.measure();
  }
  throw UnimplementedError();
}

Future<void> showRate(Benchmark benchmark) async {
  double runtime, nbhps, rtms, speed;
  runtime = await measure(benchmark);
  nbhps = 1e6 * benchmark.iter / runtime;
  speed = nbhps * benchmark.size;
  rtms = runtime.round() / 1000;

  var mark = '${formatSize(benchmark.size)} x ${benchmark.iter}';
  var message = '${benchmark.name}($mark):';
  message += ' $rtms ms';
  message += ' => ${nbhps.round()} rounds';
  message += ' @ ${formatSpeed(speed)}';
  print(message);
}

Future<void> showDiff(List<Benchmark> benchmarks) async {
  if (benchmarks.isEmpty) {
    return;
  }

  double best = 0;
  final diff = <String, double>{};
  final rate = <String, String>{};
  for (final benchmark in {...benchmarks}) {
    double runtime, speed;
    runtime = await measure(benchmark);
    speed = (1e6 * benchmark.iter * benchmark.size) / runtime;
    diff[benchmark.name] = speed;
    rate[benchmark.name] = formatSpeed(speed);
    if (speed > best) {
      best = speed;
    }
  }

  for (final name in diff.keys) {
    final speed = diff[name]!;
    var message = "$name : ${rate[name]}";
    if (speed == best) {
      message += ' [best]';
    }
    if (best < speed) {
      var p = formatDecimal(speed / best);
      message += ' => ${p}x fast';
    } else if (best > speed) {
      var p = formatDecimal(best / speed);
      message += ' => ${p}x slow';
    }
    print(message);
  }
}
