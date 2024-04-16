// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'salsa20.dart';
import 'poly1305.dart';

/// Salsa20-Poly1305 is a cryptographic algorithm combining the [Salsa20]
/// stream cipher for encryption and the [Poly1305Authenticator] for message
/// authentication.
class Salsa20Poly1305 extends Salsa20 with Poly1305Authenticator {
  @override
  String get name => "${super.name}/Poly1305";

  const Salsa20Poly1305(List<int> key) : super(key);

  @override
  Uint8List generateOTK([List<int>? nonce]) =>
      convert(Uint8List(32), nonce: nonce);
}
