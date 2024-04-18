// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show HashDigest, Poly1305, Poly1305Sink;

/// [Poly1305] is an authentication algorithm used for verifying the integrity
/// of messages. It generates a short, fixed-length tag based on a secret key
/// and the message, providing assurance that the message has not been
/// tampered with.
class Poly1305Mac extends Poly1305 {
  final List<int>? aad;

  /// Creates a new instance
  ///
  /// Parameters:
  /// - [keypair] : A 32-bytes long key.
  /// - [aad] : Additional authenticated data.
  const Poly1305Mac(
    List<int> keypair, {
    this.aad,
  }) : super(keypair);

  @override
  Poly1305AuthenticatorSink createSink() =>
      Poly1305AuthenticatorSink()..init(key, aad);
}

/// Extends the base [Poly1305Sink] to generate message digest for cipher
/// algorithms.
class Poly1305AuthenticatorSink extends Poly1305Sink {
  int _aadLength = 0;
  int _messageLength = 0;

  @override
  void init(List<int> keypair, [List<int>? aad]) {
    super.init(keypair);
    _aadLength = aad?.length ?? 0;
    if (aad != null) {
      super.add(aad);
      if (_aadLength & 15 != 0) {
        super.add(Uint8List(16 - (_aadLength & 15)));
      }
    }
    _messageLength = 0;
  }

  @override
  void add(List<int> data, [int start = 0, int? end]) {
    end ??= data.length;
    _messageLength += end - start;
    super.add(data, start, end);
  }

  @override
  HashDigest digest() {
    if (_messageLength & 15 != 0) {
      super.add(Uint8List(16 - (_messageLength & 15)));
    }

    super.add(Uint32List.fromList([
      _aadLength,
      _aadLength >>> 32,
      _messageLength,
      _messageLength >>> 32,
    ]).buffer.asUint8List());
    return super.digest();
  }
}
