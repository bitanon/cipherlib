// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show HashDigest;

/// A key pair for a Key Encapsulation Mechanism (KEM)
class KEMKeyPair {
  /// The public key used by [KEMBase.encaps] (FIPS 203: `ek`)
  final Uint8List encapsulationKey;

  /// The private key used by [KEMBase.decaps] (FIPS 203: `dk`)
  final Uint8List decapsulationKey;

  const KEMKeyPair(this.encapsulationKey, this.decapsulationKey);
}

/// A shared secret together with its encapsulation
class KEMSecret {
  /// The encapsulated form of the secret to transmit to the other party
  final Uint8List cipherText;

  /// The shared secret key
  final HashDigest sharedSecret;

  const KEMSecret(this.cipherText, this.sharedSecret);
}

/// Template for all Key Encapsulation Mechanism algorithms
abstract class KEMBase {
  const KEMBase();

  /// The name of the algorithm
  String get name;

  /// Byte length of the encapsulation key produced by [keygen]
  int get encapsulationKeySize;

  /// Byte length of the decapsulation key produced by [keygen]
  int get decapsulationKeySize;

  /// Byte length of the cipher text produced by [encaps]
  int get cipherTextSize;

  /// Byte length of the shared secret
  int get sharedSecretSize;

  /// Byte length of the seed accepted by [keygen]
  int get seedSize;

  /// Generates a random [KEMKeyPair], or a deterministic one from a [seed]
  /// of [seedSize] bytes.
  KEMKeyPair keygen({List<int>? seed});

  /// Generates a random shared secret and encapsulates it with the
  /// [encapsulationKey] of the other party.
  KEMSecret encaps(List<int> encapsulationKey);

  /// Recovers the shared secret from the [cipherText] using the
  /// [decapsulationKey].
  HashDigest decaps(List<int> decapsulationKey, List<int> cipherText);
}
