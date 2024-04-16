import 'dart:typed_data';

extension EqualityCheck on TypedData {
  bool equals(TypedData other) {
    var a = buffer.asUint32List();
    var b = other.buffer.asUint32List();
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; ++i) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

extension Uint8ListConverter on List<int> {
  Uint8List toUint8List() =>
      this is Uint8List ? (this as Uint8List) : Uint8List.fromList(this);
}
