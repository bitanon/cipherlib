// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

/// Template for Cipher algorithm sink.
abstract class CipherSink implements Sink<List<int>> {
  const CipherSink();

  /// Returns true if the sink is closed, false otherwise
  bool get closed;

  /// Resets the sink to make it ready to be used again.
  void reset();

  /// Adds [data] to the sink to returns the converted result.
  ///
  /// Throws [StateError] if called after a call to [close], with
  /// parameter [last] = true.
  @override
  Uint8List add(
    List<int> data, [
    bool last = false,
    int start,
    int? end,
  ]);

  /// Closes the sink and returns the last converted result.
  ///
  /// Same as calling `add([], true)`.
  @override
  Uint8List close();
}
