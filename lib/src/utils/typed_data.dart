// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

/// Converts a [data] to a [Uint8List].
///
/// This function is optimized for performance and should be used when converting
/// data to a [Uint8List] in hot paths.
///
/// This function will return the original input [data] as is, if it is already
/// a [TypedData] buffer and the view offset is 0 without any slicing.
/// Otherwise, a cloned instance will be returned.
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

/// Validates the length of the [key] and throws an [ArgumentError] if it is not
/// in the [allowedSizes].
///
/// Parameters:
/// - [name] : The name of the key.
/// - [key] : The key to validate.
/// - [allowedSizes] : The allowed sizes of the key.
///
/// Returns: The [Uint8List] of the [key].
/// Throws: [ArgumentError] if the length of the [key] is not in the [allowedSizes].
///
/// Example:
/// ```dart
/// validateLength('key', [1, 2, 3], {3});
/// ```
@pragma('vm:prefer-inline')
@pragma('dart2js:tryInline')
Uint8List validateLength(String name, List<int> key, Set<int> allowedSizes) {
  if (!allowedSizes.contains(key.length)) {
    final sizes = allowedSizes.toList();
    sizes.sort((a, b) => a - b);
    final text = sizes.length == 1
        ? '${sizes[0]} bytes'
        : 'one of [${sizes.join(', ')}] bytes';
    throw ArgumentError.value(key, name, 'length must be $text');
  }
  return toUint8List(key);
}
