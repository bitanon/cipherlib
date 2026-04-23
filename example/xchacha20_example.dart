import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(32);
  final nonce = randomBytes(24); // Extended nonce
  final plain = toUtf8('XChaCha20 extended nonce payload');

  final cipher = xchacha20(plain, key, nonce: nonce);
  final opened = xchacha20(cipher, key, nonce: nonce);

  print('XChaCha20');
  print('key   : ${toHex(key)}');
  print('nonce : ${toHex(nonce)}');
  print('cipher: ${toHex(cipher)}');
  print('plain : ${fromUtf8(opened)}');
}
