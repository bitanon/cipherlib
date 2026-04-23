// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/src/utils/chunk_stream.dart';
import 'package:test/test.dart';

void main() {
  group('asChunkedStream', () {
    test('throws when chunk size is non-positive', () async {
      await expectLater(
        asChunkedStream(0, Stream<int>.fromIterable(const [1, 2, 3])).toList(),
        throwsArgumentError,
      );
      await expectLater(
        asChunkedStream(-4, Stream<int>.fromIterable(const [1, 2, 3])).toList(),
        throwsArgumentError,
      );
    });

    test('emits a final partial chunk', () async {
      final chunks =
          await asChunkedStream(3, Stream<int>.fromIterable([1, 2, 3, 4, 5]))
              .toList();

      expect(
          chunks,
          equals([
            [1, 2, 3],
            [4, 5],
          ]));
    });
  });
}
