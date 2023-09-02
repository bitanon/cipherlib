// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'algorithms/xor.dart';

export 'algorithms/xor.dart';

Uint8List xor(List<int> message, List<int> key) {
  return XOR(key).convert(message);
}
