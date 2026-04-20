import 'dart:typed_data';

@pragma('vm:prefer-inline')
@pragma('dart2js:tryInline')
Uint8List toUint8List<T extends Iterable<int>>(T list) {
  if (list is Uint8List) {
    return list;
  } else if (list is ByteBuffer) {
    return Uint8List.view(list as ByteBuffer);
  } else if (list is TypedData) {
    return Uint8List.view((list as TypedData).buffer);
  } else if (list is List<int>) {
    return Uint8List.fromList(list);
  } else {
    return Uint8List.fromList(list.toList());
  }
}
