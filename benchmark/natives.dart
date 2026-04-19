// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: unused_local_variable

import 'dart:math';
import 'dart:typed_data';

import '_base.dart';

Random random = Random();

// ---------- Fill Range Benchmark ----------
class LoopFillBenchmark extends InputBenchmark {
  LoopFillBenchmark(int size) : super('loop-fill', size);

  @override
  void run() {
    final target = Uint8List(size);
    for (int i = 0; i < size; i++) {
      target[i] = input[i];
    }
  }
}

class FillRangeBenchmark extends InputBenchmark {
  FillRangeBenchmark(int size) : super('fillRange()', size);

  @override
  void run() {
    final target = Uint8List(size);
    target.fillRange(0, size, 0x9f);
  }
}

// ---------- Set Range Benchmark ----------
class LoopSetBenchmark extends InputBenchmark {
  LoopSetBenchmark(int size) : super('loop-set', size);

  @override
  void run() {
    final target = Uint8List(size);
    for (int i = 0; i < size; i++) {
      target[i] = input[i];
    }
  }
}

class SetRangeBenchmark extends InputBenchmark {
  SetRangeBenchmark(int size) : super('setRange()', size);

  @override
  void run() {
    final target = Uint8List(size)..setRange(0, size, input);
  }
}

// ---------- Reverse Range Benchmark ----------
class LoopReverseBenchmark extends InputBenchmark {
  LoopReverseBenchmark(int size) : super('loop-reverse', size);

  @override
  void run() {
    final target = Uint8List(size);
    for (int i = 0; i < size; i++) {
      target[i] = input[size - i - 1];
    }
  }
}

class SetRangeReverseBenchmark extends InputBenchmark {
  SetRangeReverseBenchmark(int size) : super('setRange()', size);

  @override
  void run() {
    final target = Uint8List(size)..setRange(0, size, input.reversed);
  }
}

// ---------- Byte Collector Benchmark ----------
class CollectInSingleListBenchmark extends SyncBenchmark {
  final Uint8List data = Uint8List.fromList(List.filled(16, 0x9f));

  CollectInSingleListBenchmark(int size)
      : super('Collect In Single List', size);

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

  CollectInSingleUint8ListBenchmark(int size)
      : super('Collect In Single Uint8List', size);

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

  CollectInChunkedListBenchmark(int size)
      : super('Collect In Chunked List', size);

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

// ------------------------------------------

Future<void> runFillRangeBenchmark() async {
  print('-------------------------------------------');
  print('|         Fill Range Benchmark             |');
  print('-------------------------------------------');
  for (var size in [5 << 20, 1 << 10, 100]) {
    print('---- message: ${formatSize(size)} ----');
    await LoopFillBenchmark(size).measureRate();
    await FillRangeBenchmark(size).measureRate();
    print('');
  }
}

Future<void> runByteCollectorBenchmark() async {
  print('-------------------------------------------');
  print('|         Byte Collector Benchmark         |');
  print('-------------------------------------------');
  for (var size in [1000, 100, 10]) {
    print('---- times: $size ----');
    await CollectInSingleListBenchmark(size).measureRate();
    await CollectInChunkedListBenchmark(size).measureRate();
    await CollectInSingleUint8ListBenchmark(size).measureRate();
    print('');
  }
}

Future<void> runSetRangeBenchmark() async {
  print('-------------------------------------------');
  print('|            Set Range Benchmark           |');
  print('-------------------------------------------');
  for (var size in [5 << 20, 1 << 10, 100]) {
    print('---- message: ${formatSize(size)} ----');
    await LoopSetBenchmark(size).measureRate();
    await SetRangeBenchmark(size).measureRate();
    print('');
  }
}

Future<void> runReverseRangeBenchmark() async {
  print('-------------------------------------------');
  print('|         Reverse Range Benchmark           |');
  print('-------------------------------------------');
  for (var size in [5 << 20, 1 << 10, 100]) {
    print('---- message: ${formatSize(size)} ----');
    await LoopReverseBenchmark(size).measureRate();
    await SetRangeReverseBenchmark(size).measureRate();
    print('');
  }
}

void main() async {
  await runSetRangeBenchmark();
  await runFillRangeBenchmark();
  await runReverseRangeBenchmark();
  await runByteCollectorBenchmark();
}
