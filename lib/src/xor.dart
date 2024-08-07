// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/src/algorithms/xor.dart';

export 'algorithms/xor.dart' show XOR;

/// Apply [XOR] cipher to the [message] using the [key].
///
/// Both the encryption and decryption can be done using this same method.
///
/// **WARNING**: This is not intended to be used for security purposes.
@pragma('vm:prefer-inline')
Uint8List xor(List<int> message, List<int> key) =>
    XOR.fromList(key).convert(message);

/// Apply [XOR] cipher to the message [stream] using the [key].
///
/// Both the encryption and decryption can be done using this same method.
///
/// **WARNING**: This is not intended to be used for security purposes.
@pragma('vm:prefer-inline')
Stream<int> xorStream(Stream<int> stream, List<int> key) =>
    XOR.fromList(key).stream(stream);
