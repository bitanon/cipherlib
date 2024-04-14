// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'algorithms/xor.dart';

export 'algorithms/xor.dart' show XOR;

/// Apply [XOR] cipher to the [message] using the [key].
///
/// Both the encryption and decryption can be done using this same method.
///
/// **WARNING**: This is not intended to be used for security purposes.
Uint8List xor(List<int> message, List<int> key) {
  return XOR(key).convert(message);
}

/// Apply [XOR] cipher to the message [stream] using the [key].
///
/// Both the encryption and decryption can be done using this same method.
///
/// **WARNING**: This is not intended to be used for security purposes.
Stream<int> xorPipe(Stream<int> stream, List<int> key) {
  return XOR(key).pipe(stream);
}
