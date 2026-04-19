// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: unused_local_variable

import 'dart:math';
import 'dart:typed_data';

import '_base.dart';

Random random = Random();

// ---------- Byte Collector Benchmark ----------
class CollectInSingleListBenchmark extends SyncBenchmark {
  final Uint8List data = Uint8List.fromList(List.filled(16, 0x9f));

  CollectInSingleListBenchmark(int size, int iter)
      : super('Collect In Single List', size, iter);

  @override
  void run() {
    List<int> list = [];
    var length = 0;
    for (var i = 0; i < size; i++) {
      list.addAll(data);
      length += data.length;
    }
    var result = Uint8List.fromList(list);
  }
}

class CollectInSingleUint8ListBenchmark extends SyncBenchmark {
  final Uint8List data = Uint8List.fromList(List.filled(16, 0x9f));

  CollectInSingleUint8ListBenchmark(int size, int iter)
      : super('Collect In Single Uint8List', size, iter);

  @override
  void run() {
    Uint8List list = Uint8List(1024);
    var length = 0;
    for (var i = 0; i < size; i++) {
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

class CollectInChunkedListBenchmark extends SyncBenchmark {
  final Uint8List data = Uint8List.fromList(List.filled(16, 0x9f));

  CollectInChunkedListBenchmark(int size, int iter)
      : super('Collect In Chunked List', size, iter);

  @override
  void run() {
    List<List<int>> list = [];
    var length = 0;
    for (int i = 0; i < size; i++) {
      list.add(data);
      length += data.length;
    }
    int pos = 0;
    var result = Uint8List(length);
    for (var item in list) {
      result.setRange(pos, pos + item.length, item);
      pos += item.length;
    }
  }
}

// ---------- Set Range Benchmark ----------
class LoopSetBenchmark extends InputBenchmark {
  LoopSetBenchmark(int size, int iter) : super('loop-set', size, iter);

  @override
  void run() {
    final target = Uint8List(size);
    for (int i = 0; i < size; i++) {
      target[i] = input[i];
    }
  }
}

class SetRangeBenchmark extends InputBenchmark {
  SetRangeBenchmark(int size, int iter) : super('setRange()', size, iter);

  @override
  void run() {
    final target = Uint8List(size)..setRange(0, size, input);
  }
}

// ---------- Fill Range Benchmark ----------
class LoopFillBenchmark extends InputBenchmark {
  LoopFillBenchmark(int size, int iter) : super('loop-fill', size, iter);

  @override
  void run() {
    final target = Uint8List(size);
    for (int i = 0, j = size - 1; i < size; i++, j--) {
      target[i] = input[j];
    }
  }
}

class FillRangeBenchmark extends InputBenchmark {
  FillRangeBenchmark(int size, int iter) : super('fillRange()', size, iter);

  @override
  void run() {
    final target = Uint8List(size);
    target.fillRange(0, size, 0x9f);
  }
}

// ---------- Reverse Range Benchmark ----------
class LoopReverseBenchmark extends InputBenchmark {
  LoopReverseBenchmark(int size, int iter) : super('loop-reverse', size, iter);

  @override
  void run() {
    final target = Uint8List(size);
    for (int i = 0; i < size; i++) {
      target[i] = input[size - i - 1];
    }
  }
}

class SetRangeReverseBenchmark extends InputBenchmark {
  SetRangeReverseBenchmark(int size, int iter)
      : super('setRange()', size, iter);

  @override
  void run() {
    final target = Uint8List(size)..setRange(0, size, input.reversed);
  }
}

// ------------------------------------------

Future<void> runByteCollectorBenchmark() async {
  print('-------------------------------------------');
  print('|         Byte Collector Benchmark         |');
  print('-------------------------------------------');
  for (var condition in [
    [1000, 100],
    [100, 5000],
    [10, 10000],
  ]) {
    int times = condition[0];
    int iter = condition[1];
    print('---- times: $times | iterations: $iter ----');
    await CollectInSingleListBenchmark(times, iter).measureRate();
    await CollectInChunkedListBenchmark(times, iter).measureRate();
    await CollectInSingleUint8ListBenchmark(times, iter).measureRate();
    print('');
  }
}

Future<void> runSetRangeBenchmark() async {
  print('-------------------------------------------');
  print('|            Set Range Benchmark           |');
  print('-------------------------------------------');
  for (var condition in [
    [5 << 20, 100],
    [1 << 10, 50000],
    [100, 100000],
  ]) {
    int size = condition[0];
    int iter = condition[1];
    print('---- message: ${formatSize(size)} | iterations: $iter ----');
    await LoopSetBenchmark(size, iter).measureRate();
    await SetRangeBenchmark(size, iter).measureRate();
    print('');
  }
}

Future<void> runFillRangeBenchmark() async {
  print('-------------------------------------------');
  print('|         Fill Range Benchmark             |');
  print('-------------------------------------------');
  for (var condition in [
    [5 << 20, 100],
    [1 << 10, 50000],
    [100, 100000],
  ]) {
    int size = condition[0];
    int iter = condition[1];
    print('---- message: ${formatSize(size)} | iterations: $iter ----');
    await LoopFillBenchmark(size, iter).measureRate();
    await FillRangeBenchmark(size, iter).measureRate();
    print('');
  }
}

Future<void> runReverseRangeBenchmark() async {
  print('-------------------------------------------');
  print('|         Reverse Range Benchmark           |');
  print('-------------------------------------------');
  for (var condition in [
    [5 << 20, 100],
    [1 << 10, 50000],
    [100, 100000],
  ]) {
    int size = condition[0];
    int iter = condition[1];
    print('---- message: ${formatSize(size)} | iterations: $iter ----');
    await LoopReverseBenchmark(size, iter).measureRate();
    await SetRangeReverseBenchmark(size, iter).measureRate();
    print('');
  }
}

void main() async {
  await runFillRangeBenchmark();
  await runSetRangeBenchmark();
  await runReverseRangeBenchmark();
  await runByteCollectorBenchmark();
}
