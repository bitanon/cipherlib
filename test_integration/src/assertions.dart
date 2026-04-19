import 'package:cipherlib/codecs.dart';

bool bytesEq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

void expectSameUtf8(List<int> got, String want) {
  final s = fromUtf8(got);
  if (s != want) {
    throw StateError('expected UTF-8 "$want", got "$s"');
  }
}
