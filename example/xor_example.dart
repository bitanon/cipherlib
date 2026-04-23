import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(16);
  final plain = toUtf8('quick reversible masking');

  final masked = xor(plain, key);
  final unmasked = xor(masked, key);

  print('XOR');
  print('key    : ${toHex(key)}');
  print('masked : ${toHex(masked)}');
  print('unmasked: ${fromUtf8(unmasked)}');
}
