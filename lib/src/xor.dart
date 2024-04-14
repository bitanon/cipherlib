// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'algorithms/xor.dart';

export 'algorithms/xor.dart' show XOR;

/// Apply [XOR] encryption to the [message] using the [key].
///
/// Since [XOR] is a [Symmetric Key Cipher][symkey], encryption and decryption can be
/// done using the same method.
///
/// **WARNING**: This is not intended to be used for security purposes.
///
/// [symkey]: https://en.wikipedia.org/wiki/Symmetric-key_algorithm
Uint8List xor(List<int> message, List<int> key) {
  return XOR(key).convert(message);
}

/// Apply [XOR] encryption to the [message] stream using the [key].
///
/// Since [XOR] is a [Symmetric Key Cipher][symkey], encryption and decryption can be
/// done using the same method.
///
/// **WARNING**: This is not intended to be used for security purposes.
///
/// [symkey]: https://en.wikipedia.org/wiki/Symmetric-key_algorithm
Stream<int> xorPipe(Stream<int> message, List<int> key) {
  return XOR(key).pipe(message);
}
