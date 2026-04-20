// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';

/// Minimum number of milliseconds each benchmark should run to ensure accuracy.
const int warmupDurationMillis = 100;
const int exerciseDurationMillis = 2000;

// ------------ Interface Classes ------------
abstract class Benchmark {
  final int size;
  final String name;

  const Benchmark(this.name, this.size);

  /// Measures the score for the benchmark.
  Future<void> measureRate() async {
    await showRate(this);
  }

  /// Measures the difference between the benchmark and the others.
  Future<void> measureDiff([List<Benchmark> others = const []]) async {
    await showDiff([this, ...others]);
  }
}

class Measurement {
  Measurement(this._micros, this._iter, this._bytes);

  final int _iter;
  final int _bytes;
  final int _micros;

  /// Total number of iterations.
  late final rounds = _iter;

  /// Average runtime in microseconds.
  late final runtimeMicros = _micros / _iter;

  /// Average runtime in milliseconds.
  late final runtimeMillis = runtimeMicros / 1000;

  /// Average runtime in seconds.
  late final runtimeSeconds = runtimeMillis / 1000;

  /// Number of iterations per second.
  late double rate = 1e6 * _iter / _micros;

  /// Throughput or bandwidth (bytes per second).
  late double speed = _bytes * rate;

  /// Size in human readable string.
  late final String sizeString = formatSize(_bytes);

  /// Speed in human readable string.
  late final String speedString = formatSpeed(speed);
}

// ------------ Main Classes ------------

abstract class SyncBenchmark extends Benchmark {
  const SyncBenchmark(super.name, super.size);

  /// The benchmark code.
  void run();

  /// Not measured setup code executed prior to the benchmark runs.
  void setup() {}

  /// Not measured teardown code executed after the benchmark runs.
  void teardown() {}

  /// Measures the score for the benchmark and returns it.
  Measurement measure() {
    final watch = Stopwatch()..start();
    final warmupMicros = warmupDurationMillis * 1000;
    final excerciseMicros = exerciseDurationMillis * 1000;
    final exerciseJitter = excerciseMicros * 0.1;

    // warmup
    setup();
    run();

    // probe: find how many iterations fit in 1ms
    int iter = 0;
    int micros = 0;
    while (micros < warmupMicros) {
      watch.reset();
      run();
      run();
      micros += watch.elapsedMicroseconds;
      iter += 2;
    }

    // calculate batch size for 1ms runtime (min 10)
    int batch = (1000 * iter / micros).ceil();
    if (batch < 10) batch = 10;

    // exercise: measure time in batches
    iter = 0;
    micros = 0;
    while (micros + exerciseJitter < excerciseMicros) {
      watch.reset();
      for (int i = 0; i < batch; ++i) {
        run();
      }
      micros += watch.elapsedMicroseconds;
      iter += batch;
    }

    watch.stop();
    teardown();
    return Measurement(micros, iter, size);
  }
}

abstract class AsyncBenchmark extends Benchmark {
  AsyncBenchmark(super.name, super.size);

  /// The benchmark code.
  Future<void> run();

  /// Not measured setup code executed prior to the benchmark runs.
  Future<void> setup() async {}

  /// Not measures teardown code executed after the benchmark runs.
  Future<void> teardown() async {}

  /// Measures the score for the benchmark and returns it.
  Future<Measurement> measure() async {
    final watch = Stopwatch()..start();
    final warmupMicros = warmupDurationMillis * 1000;
    final excerciseMicros = exerciseDurationMillis * 1000;
    final exerciseJitter = excerciseMicros * 0.1;

    // warmup
    await setup();
    await run();

    // probe: find how many iterations fit in 1ms
    int iter = 0;
    int micros = 0;
    while (micros < warmupMicros) {
      watch.reset();
      await run();
      await run();
      micros += watch.elapsedMicroseconds;
      iter += 2;
    }

    // calculate batch size for 1ms runtime (min 10)
    int batch = (1000 * iter / micros).ceil();
    if (batch < 10) batch = 10;

    // exercise: measure time in batches
    iter = 0;
    micros = 0;
    while (micros + exerciseJitter < excerciseMicros) {
      watch.reset();
      for (int i = 0; i < batch; ++i) {
        await run();
      }
      micros += watch.elapsedMicroseconds;
      iter += batch;
    }

    watch.stop();
    await teardown();
    return Measurement(micros, iter, size);
  }
}

/// ------------ Utility Functions ------------

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
    'bps',
    'Kbps',
    'Mbps',
    'Gbps',
    'Tbps',
    'Pbps',
    'Ebps',
    'Zbps',
    'Ybps',
  ];
  for (i = 0; size >= 1000; i++) {
    size /= 1000;
  }
  if (size >= 100) {
    size = size.roundToDouble();
  }
  return '${formatDecimal(size)} ${suffix[i]}';
}

Future<Measurement> measure(Benchmark benchmark) async {
  if (benchmark is SyncBenchmark) {
    return benchmark.measure();
  } else if (benchmark is AsyncBenchmark) {
    return await benchmark.measure();
  }
  throw UnimplementedError();
}

Future<void> showRate(Benchmark benchmark) async {
  final result = await measure(benchmark);
  var message = '${benchmark.name}(${result.sizeString}):';
  message += ' ${result.runtimeMillis} ms';
  message += ' => ${result.rate.round()} rounds';
  message += ' @ ${result.speedString}';
  print(message);
}

Future<void> showDiff(List<Benchmark> benchmarks) async {
  if (benchmarks.isEmpty) {
    return;
  }

  double best = 0;
  final diff = <String, Measurement>{};
  for (final benchmark in {...benchmarks}) {
    final result = await measure(benchmark);
    diff[benchmark.name] = result;
    if (result.speed > best) {
      best = result.speed;
    }
  }

  for (final name in diff.keys) {
    final result = diff[name]!;
    var message = "$name : ${result.speedString}";
    if (result.speed == best) {
      message += ' [best]';
    }
    if (best < result.speed) {
      var p = formatDecimal(result.speed / best);
      message += ' => ${p}x fast';
    } else if (best > result.speed) {
      var p = formatDecimal(best / result.speed);
      message += ' => ${p}x slow';
    }
    print(message);
  }
}
