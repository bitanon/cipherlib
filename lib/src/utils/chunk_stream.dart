import 'dart:async';

/// Wrap [input] as a chunked stream with chunks the size of [N].
///
/// This function returns a [Stream<List<T>>] where each event is a [List<T>]
/// with [N] elements. The last chunk of the resulting stream may contain less
/// than [N] elements.
///
/// This is useful for batch processing elements from a stream.
Stream<List<T>> asChunkedStream<T>(int N, Stream<T> input) async* {
  if (N <= 0) {
    throw ArgumentError.value(N, 'N', 'chunk size must be >= 0');
  }

  var events = <T>[];
  await for (final event in input) {
    events.add(event);
    if (events.length == N) {
      yield events;
      events = <T>[];
    }
  }

  if (events.isNotEmpty) {
    yield events;
  }
}
