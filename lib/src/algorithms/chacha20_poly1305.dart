// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';
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

  const ChaCha20Poly1305._(Uint8List key, Uint8List iv, this._aead)
      : super(key, iv);

  factory ChaCha20Poly1305({
    required List<int> key,
    required List<int> iv,
    List<int>? aad,
  }) =>
      ChaCha20.fromList(key, iv).poly1305(aad);

  @override
  String get name => "${super.name}/${_aead.name}";

  @override
  HashDigest verify(List<int> message, [List<int>? mac]) {
    if (mac == null) {
      return _aead.convert(convert(message));
    }
    var my = _aead.convert(message);
    if (!my.isEqual(mac)) {
      throw AssertionError('Message authenticity check failed');
    }
    return my;
  }

  @override
  Future<HashDigest> verifyBufferedStream(
    Stream<List<int>> stream, [
    Future<List<int>>? mac,
  ]) async {
    if (mac == null) {
      return await _aead.bind(bind(stream)).first;
    }
    var my = await _aead.bind(stream).first;
    if (!my.isEqual(await mac)) {
      throw AssertionError('Message authenticity check failed');
    }
    return my;
  }
}

extension ChaCha20Poly1305Extention on ChaCha20 {
  @pragma('vm:prefer-inline')
  ChaCha20Poly1305 poly1305([List<int>? aad]) {
    var otk = ChaCha20Sink(key, iv, 0).add(Uint8List(32));
    var aead = Poly1305AEAD(otk, aad);
    return ChaCha20Poly1305._(key, iv, aead);
  }
}
