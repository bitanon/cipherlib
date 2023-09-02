import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';

void main() {
  var key = [0x54];
  var inp = [0x03, 0xF1];
  print('text: ${toBinary(inp)}');
  print(' key: ${toBinary(key)}');
  print(' XOR: ${toBinary(xor(inp, key))}');
}
