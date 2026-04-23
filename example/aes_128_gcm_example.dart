import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(16); // AES-128
  final nonce = randomBytes(12); // Recommended IV size for GCM
  final aad = toUtf8('env=prod');
  final plain = toUtf8('AES-128-GCM payload');

  final aes = AES(key).gcm(nonce, aad: aad);
  final sealed = aes.encrypt(plain);
  final opened = aes.decrypt(sealed);

  print('AES-128-GCM');
  print('key   : ${toHex(key)}');
  print('nonce : ${toHex(nonce)}');
  print('aad   : ${fromUtf8(aad)}');
  print('cipher: ${toHex(sealed)}');
  print('plain : ${fromUtf8(opened)}');
}
