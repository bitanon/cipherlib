// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'chacha20.dart';
import 'poly1305.dart';

/// ChaCha20-Poly1305 is a cryptographic algorithm combining the [ChaCha20]
/// stream cipher for encryption and the [Poly1305Authenticator] for message
/// authentication. It provides both confidentiality and integrity protection,
/// making it a popular choice for secure communication protocols like TLS.
///
/// This implementation is based on the [RFC-8439][rfc]
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc8439.html
class ChaCha20Poly1305 extends ChaCha20 with Poly1305Authenticator {
  @override
  String get name => "${super.name}/Poly1305";

  const ChaCha20Poly1305(List<int> key) : super(key);

  @override
  Uint8List generateOTK([List<int>? nonce]) => convert(
        Uint8List(32),
        nonce: nonce,
        blockCount: 0,
      );
}
