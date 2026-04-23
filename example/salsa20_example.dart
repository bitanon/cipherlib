import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(32);
  final nonce = randomBytes(8);
  final plain = toUtf8('Salsa20 message');

  final cipher = salsa20(plain, key, nonce: nonce);
  final opened = salsa20(cipher, key, nonce: nonce);

  print('Salsa20');
  print('key   : ${toHex(key)}');
  print('nonce : ${toHex(nonce)}');
  print('cipher: ${toHex(cipher)}');
  print('plain : ${fromUtf8(opened)}');
}
