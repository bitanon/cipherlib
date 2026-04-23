import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(32);
  final nonce = randomBytes(12);
  final plain = toUtf8('ChaCha20 stream cipher payload');

  final cipher = chacha20(plain, key, nonce: nonce);
  final opened = chacha20(cipher, key, nonce: nonce);

  print('ChaCha20');
  print('key   : ${toHex(key)}');
  print('nonce : ${toHex(nonce)}');
  print('cipher: ${toHex(cipher)}');
  print('plain : ${fromUtf8(opened)}');
}
