// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher.dart';
import 'package:hashlib/hashlib.dart' show HashDigest;

import 'poly1305.dart';
import 'salsa20.dart';

/// Salsa20-Poly1305 is a cryptographic algorithm combining the [Salsa20]
/// stream cipher for encryption and the [Poly1305AEAD] for generating message
/// authentication code.
class Salsa20Poly1305 extends Salsa20 with AEADCipher {
  final Poly1305AEAD _aead;

  const Salsa20Poly1305._(Uint8List key, Uint8List iv, this._aead)
      : super(key, iv);

  factory Salsa20Poly1305({
    required List<int> key,
    required List<int> iv,
    List<int>? aad,
  }) =>
      Salsa20.fromList(key, iv).poly1305(aad);

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

extension Salsa20Poly1305Extention on Salsa20 {
  @pragma('vm:prefer-inline')
  Salsa20Poly1305 poly1305([List<int>? aad]) {
    var otk = Salsa20Sink(key, iv, 0).add(Uint8List(32));
    var aead = Poly1305AEAD(otk, aad);
    return Salsa20Poly1305._(key, iv, aead);
  }
}
