// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'core/cipher.dart';
import 'utils/chunk_stream.dart';

/// Provides support for streaming single byte values using a [StreamCipher].
extension StreamCipherExtension on StreamCipher {
  /// Transforms the [stream] of message bytes using the algorithm.
  Stream<int> stream(Stream<int> stream, [int chunkSize = 1024]) async* {
    final chunk = asChunkedStream(chunkSize, stream);
    await for (var data in bind(chunk)) {
      for (var byte in data) {
        yield byte;
      }
    }
  }
}
