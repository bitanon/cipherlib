// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/aead_cipher.dart';
import 'package:hashlib/hashlib.dart' show HashDigest;

import 'chacha20.dart';
import 'poly1305.dart';

/// ChaCha20-Poly1305 is a cryptographic algorithm combining the [ChaCha20]
/// stream cipher for encryption andthe [Poly1305AEAD] for generating message
/// authentication code.
/// It provides both confidentiality and integrity protection, making it a
/// popular choice for secure communication protocols like TLS.
///
/// This implementation is based on the [RFC-8439][rfc]
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc8439.html
class ChaCha20Poly1305 extends ChaCha20 with AEADCipher {
  final Poly1305AEAD _aead;

  @override
  String get name => "${super.name}/${_aead.name}";

  const ChaCha20Poly1305._(
    Uint8List key,
    Uint8List iv,
    this._aead,
  ) : super(key, iv);

  factory ChaCha20Poly1305({
    required List<int> key,
    required List<int> iv,
    List<int>? aad,
  }) =>
      ChaCha20.fromList(key, iv).poly1305(aad);

  @override
  void resetSalt() {
    super.resetSalt();
    var otk = ChaCha20Sink(key, salt, 0).add(Uint8List(32));
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
      salt: salt,
      mac: digest,
      message: cipher,
    );
  }
}

/// Adds [poly1305] to [ChaCha20] to create an instance of [ChaCha20Poly1305]
extension ChaCha20ExtentionForPoly1305 on ChaCha20 {
  @pragma('vm:prefer-inline')
  ChaCha20Poly1305 poly1305([List<int>? aad]) {
    var otk = ChaCha20Sink(key, salt, 0).add(Uint8List(32));
    var aead = Poly1305AEAD(otk, aad);
    return ChaCha20Poly1305._(key, salt, aead);
  }
}
