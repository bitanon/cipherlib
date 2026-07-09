// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// pqcrypto's KEM API returns Dart records, which this package's 2.19 language
// version cannot reference statically — those call sites go through `dynamic`.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:pqcrypto/pqcrypto.dart' as pqc;

import '_base.dart';

class CipherlibKeygenBenchmark extends SyncBenchmark {
  final MLKEM kem;
  final Uint8List seed;
  CipherlibKeygenBenchmark(this.kem)
      : seed = Uint8List(kem.seedSize),
        super('cipherlib', kem.seedSize);

  @override
  dynamic run() {
    return kem.keygen(seed: seed);
  }
}

class PqcryptoKeygenBenchmark extends SyncBenchmark {
  final dynamic kem;
  final Uint8List seed;
  PqcryptoKeygenBenchmark(this.kem)
      : seed = Uint8List(64),
        super('pqcrypto', 64);

  @override
  dynamic run() {
    return kem.generateKeyPair(seed);
  }
}

class CipherlibEncapsBenchmark extends SyncBenchmark {
  final MLKEM kem;
  late Uint8List ek;
  CipherlibEncapsBenchmark(this.kem) : super('cipherlib', kem.cipherTextSize);

  @override
  void setup() {
    ek = kem.keygen().encapsulationKey;
  }

  @override
  dynamic run() {
    return kem.encaps(ek);
  }
}

class PqcryptoEncapsBenchmark extends SyncBenchmark {
  final MLKEM other;
  final dynamic kem;
  late Uint8List ek;
  PqcryptoEncapsBenchmark(this.other, this.kem)
      : super('pqcrypto', other.cipherTextSize);

  @override
  void setup() {
    ek = other.keygen().encapsulationKey;
  }

  @override
  dynamic run() {
    return kem.encapsulate(ek);
  }
}

class CipherlibDecapsBenchmark extends SyncBenchmark {
  final MLKEM kem;
  late Uint8List dk;
  late Uint8List ct;
  CipherlibDecapsBenchmark(this.kem) : super('cipherlib', kem.cipherTextSize);

  @override
  void setup() {
    final keys = kem.keygen();
    dk = keys.decapsulationKey;
    ct = kem.encaps(keys.encapsulationKey).cipherText;
  }

  @override
  dynamic run() {
    return kem.decaps(dk, ct);
  }
}

class PqcryptoDecapsBenchmark extends SyncBenchmark {
  final MLKEM other;
  final dynamic kem;
  late Uint8List dk;
  late Uint8List ct;
  PqcryptoDecapsBenchmark(this.other, this.kem)
      : super('pqcrypto', other.cipherTextSize);

  @override
  void setup() {
    final keys = other.keygen();
    dk = keys.decapsulationKey;
    ct = other.encaps(keys.encapsulationKey).cipherText;
  }

  @override
  dynamic run() {
    return kem.decapsulate(dk, ct);
  }
}

void main() async {
  final levels = {
    MLKEM.kem512(): pqc.PqcKem.kyber512,
    MLKEM.kem768(): pqc.PqcKem.kyber768,
    MLKEM.kem1024(): pqc.PqcKem.kyber1024,
  };
  for (final entry in levels.entries) {
    final kem = entry.key;
    final other = entry.value;
    print('---- ${kem.name} Keygen ----');
    await CipherlibKeygenBenchmark(kem).measureDiff([
      PqcryptoKeygenBenchmark(other),
    ]);
    print('');
    print('---- ${kem.name} Encaps ----');
    await CipherlibEncapsBenchmark(kem).measureDiff([
      PqcryptoEncapsBenchmark(kem, other),
    ]);
    print('');
    print('---- ${kem.name} Decaps ----');
    await CipherlibDecapsBenchmark(kem).measureDiff([
      PqcryptoDecapsBenchmark(kem, other),
    ]);
    print('');
  }
}
