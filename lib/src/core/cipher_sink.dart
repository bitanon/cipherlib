// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

/// Template for Cipher algorithm sink.
@Deprecated('will be removed soon')
abstract class CipherSink implements Sink<List<int>> {
  bool _closed = false;

  /// Returns true if the sink is closed, false otherwise
  bool get closed => _closed;

  /// Resets the sink to make it ready to be used again.
  void reset() {
    _closed = false;
  }

  /// Closes the sink and returns the last converted result.
  ///
  /// Same as calling `add([], true)`.
  @override
  Uint8List close() => add([], true);

  /// Adds [data] to the sink to returns the converted result.
  ///
  /// Throws [StateError] if called after a call to [close], with
  /// parameter [last] = true.
  @override
  Uint8List add(
    List<int> data, [
    bool last = false,
    int start = 0,
    int? end,
  ]) {
    if (start < 0) {
      throw RangeError.range(start, 0, data.length);
    }
    if (_closed) {
      throw StateError('The sink is closed');
    }
    _closed = last;
    end ??= data.length;
    if (end > data.length) {
      throw RangeError.range(end, 0, data.length);
    }
    if (start > end) {
      throw ArgumentError('start must be less than end');
    }
    return $add(data, start, end);
  }

  /// Processes the data and returns the converted result.
  ///
  /// This method is used by the [add] method to process the data.
  /// It is implemented by the concrete cipher sink classes.
  @pragma('vm:prefer-inline')
  Uint8List $add(List<int> data, int start, int end);
}
