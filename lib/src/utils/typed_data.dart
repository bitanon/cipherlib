// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

@pragma('vm:prefer-inline')
@pragma('dart2js:tryInline')
Uint8List toUint8List<T extends Iterable<int>>(T data) {
  if (data is Uint8List) {
    if (data.offsetInBytes == 0 && data.length == data.buffer.lengthInBytes) {
      return data;
    }
    return data.sublist(0);
  } else if (data is TypedData) {
    final td = data as TypedData;
    if (td.offsetInBytes == 0 && td.lengthInBytes == td.buffer.lengthInBytes) {
      return Uint8List.view(td.buffer);
    }
    return Uint8List.view(
      td.buffer,
      td.offsetInBytes,
      td.lengthInBytes,
    ).sublist(0);
  } else if (data is List<int>) {
    return Uint8List.fromList(data);
  } else {
    return Uint8List.fromList(data.toList());
  }
}
