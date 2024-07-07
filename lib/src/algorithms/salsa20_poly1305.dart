// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/aead_cipher.dart';
import 'package:hashlib/hashlib.dart' show HashDigest;

import 'salsa20.dart';
import 'poly1305.dart';

/// Salsa20-Poly1305 is a cryptographic algorithm combining the [Salsa20]
/// stream cipher for encryption and the [Poly1305AEAD] for generating message
/// authentication code.
class Salsa20Poly1305 extends Salsa20 with AEADCipher {
  final Poly1305AEAD _aead;

  @override
  String get name => "${super.name}/${_aead.name}";

  const Salsa20Poly1305._(
    Uint8List key,
    Uint8List iv,
    this._aead,
  ) : super(key, iv);

  factory Salsa20Poly1305({
    required List<int> key,
    required List<int> iv,
    List<int>? aad,
  }) =>
      Salsa20.fromList(key, iv).poly1305(aad);

  @override
  void resetIV() {
    super.resetIV();
    var otk = Salsa20Sink(key, iv, 0).add(Uint8List(32));
    _aead.key.setAll(0, otk);
  }

  @override
  AEADResult verify(List<int> message, [List<int>? mac]) {
    var cipher = convert(message);
    HashDigest digest;
    if (mac == null) {
      digest = _aead.convert(cipher);
    } else {
      digest = _aead.convert(message);
      if (!digest.isEqual(mac)) {
        throw AssertionError('Message authenticity check failed');
      }
    }
    return AEADResult(
      iv: iv,
      mac: digest,
      message: cipher,
    );
  }
}

/// Adds [poly1305] to [Salsa20] to create an instance of [Salsa20Poly1305]
extension Salsa20ExtentionForPoly1305 on Salsa20 {
  @pragma('vm:prefer-inline')
  Salsa20Poly1305 poly1305([List<int>? aad]) {
    var otk = Salsa20Sink(key, iv, 0).add(Uint8List(32));
    var aead = Poly1305AEAD(otk, aad);
    return Salsa20Poly1305._(key, iv, aead);
  }
}
