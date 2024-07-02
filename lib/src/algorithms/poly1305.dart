// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/src/core/aead_mac_sink.dart';
import 'package:hashlib/hashlib.dart' show MACHashBase, Poly1305Sink;

/// The Poly1305 MAC intended to be used by AEAD ciphers
class Poly1305AEAD extends MACHashBase {
  @override
  final String name = 'Poly1305';

  /// Additional Authenticated Data (optional)
  final List<int>? aad;

  /// Creates an instance for AEAD cipher based on [Poly1305Sink] with
  /// additional authenticated data [aad]
  const Poly1305AEAD(List<int> keypair, this.aad) : super(keypair);

  @override
  MACSinkForAEAD createSink() => MACSinkForAEAD(Poly1305Sink(), aad)..init(key);
}
