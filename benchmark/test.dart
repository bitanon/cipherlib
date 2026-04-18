// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:math';
import 'dart:typed_data';

import 'base.dart';

Random random = Random();

class LoopBenchmark extends Benchmark {
  late final Uint8List inp = Uint8List.fromList(input);
  final Uint8List key = Uint8List.fromList(List.filled(100, 0x9f));

  LoopBenchmark(int size, int iter) : super('loop', size, iter);

  @override
  void run() {
    for (var i = 0; i < 100; i++) {
      inp[i] = key[i];
    }
  }
}

class SetRangeBenchmark extends Benchmark {
  late final Uint8List inp = Uint8List.fromList(input);
  final Uint8List key = Uint8List.fromList(List.filled(100, 0x9f));

  SetRangeBenchmark(int size, int iter) : super('loop', size, iter);

  @override
  void run() {
    inp.setRange(0, 100, key);
  }
}

class SetAllBenchmark extends Benchmark {
  late final Uint8List inp = Uint8List.fromList(input);
  final Uint8List key = Uint8List.fromList(List.filled(100, 0x9f));

  SetAllBenchmark(int size, int iter) : super('loop', size, iter);

  @override
  void run() {
    inp.setAll(0, key);
  }
}

class ExpandIntListBenchmark extends Benchmark {
  final int times;
  final List<int> list = <int>[];
  final Uint8List data = Uint8List.fromList(List.filled(16, 0x9f));

  ExpandIntListBenchmark(this.times, int iter) : super('List<int>', 0, iter);

  @override
  int get size => times * data.length;

  @override
  void run() {
    var length = 0; // ignore: unused_local_variable
    for (var i = 0; i < times; i++) {
      list.addAll(data);
      length += data.length;
    }
    var result = Uint8List.fromList(list); // ignore: unused_local_variable
  }
}

class ExpandUint8ListBenchmark extends Benchmark {
  final int times;
  Uint8List list = Uint8List(1024);
  final Uint8List data = Uint8List.fromList(List.filled(16, 0x9f));

  ExpandUint8ListBenchmark(this.times, int iter)
      : super('List<Uint8List>', 0, iter);

  @override
  int get size => times * data.length;

  @override
  void run() {
    var length = 0;
    for (var i = 0; i < times; i++) {
      int n = length + data.length;
      if (n > list.length) {
        int m = n - list.length;
        if (m < 1024) m = 1024;
        var p = Uint8List(list.length + m);
        p.setRange(0, length, list);
        list = p;
      }
      list.setRange(length, n, data);
      length += data.length;
    }
    list = list.sublist(0, length);
  }
}

void main() async {
  for (var condition in [
    [1000, 100],
    [100, 5000],
    [10, 10000],
  ]) {
    int times = condition[0];
    int iter = condition[1];
    print('---- times: $times | iterations: $iter ----');
    ExpandIntListBenchmark(times, iter).measureRate();
    ExpandUint8ListBenchmark(times, iter).measureRate();
    print('');
  }
  // for (var condition in [
  //   [5 << 20, 100],
  //   [1 << 10, 50000],
  //   [100, 100000],
  // ]) {
  //   int size = condition[0];
  //   int iter = condition[1];
  //   print('---- message: ${formatSize(size)} | iterations: $iter ----');
  //   LoopBenchmark(size, iter).measureRate();
  //   SetAllBenchmark(size, iter).measureRate();
  //   SetRangeBenchmark(size, iter).measureRate();
  //   print('');
  // }
}
