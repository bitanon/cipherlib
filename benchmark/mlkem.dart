// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';

import '_base.dart';

class MLKEMKeygenBenchmark extends SyncBenchmark {
  final MLKEM kem;
  final Uint8List seed;
  MLKEMKeygenBenchmark(this.kem)
      : seed = Uint8List(kem.seedSize),
        super('keygen', kem.seedSize);

  @override
  void run() {
    kem.keygen(seed: seed);
  }
}

class MLKEMEncapsBenchmark extends SyncBenchmark {
  final MLKEM kem;
  late Uint8List ek;
  MLKEMEncapsBenchmark(this.kem) : super('encaps', kem.cipherTextSize);

  @override
  void setup() {
    ek = kem.keygen().encapsulationKey;
  }

  @override
  void run() {
    kem.encaps(ek);
  }
}

class MLKEMDecapsBenchmark extends SyncBenchmark {
  final MLKEM kem;
  late Uint8List dk;
  late Uint8List ct;
  MLKEMDecapsBenchmark(this.kem) : super('decaps', kem.cipherTextSize);

  @override
  void setup() {
    final keys = kem.keygen();
    dk = keys.decapsulationKey;
    ct = kem.encaps(keys.encapsulationKey).cipherText;
  }

  @override
  void run() {
    kem.decaps(dk, ct);
  }
}

void main() async {
  for (final kem in [MLKEM.kem512(), MLKEM.kem768(), MLKEM.kem1024()]) {
    print('---- ${kem.name} ----');
    await MLKEMKeygenBenchmark(kem).measureRate();
    await MLKEMEncapsBenchmark(kem).measureRate();
    await MLKEMDecapsBenchmark(kem).measureRate();
    print('');
  }
}
