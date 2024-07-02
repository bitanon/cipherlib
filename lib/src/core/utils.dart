Stream<List<E>> asBufferedStream<E>(Stream<E> stream, int bufferSize) async* {
  int p = bufferSize;
  List<E> buffer = [];
  await for (var x in stream) {
    if (buffer.length < bufferSize) {
      buffer.add(x);
    } else {
      if (p == bufferSize) {
        yield List.of(buffer);
        p = 0;
      }
      buffer[p++] = x;
    }
  }
  if (buffer.length < bufferSize) {
    yield buffer;
  } else if (p > 0) {
    yield buffer.sublist(0, p);
  }
}
