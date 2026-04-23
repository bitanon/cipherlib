import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(32); // AES-256
  final nonce = randomBytes(12); // Recommended IV size for GCM
  final aad = toUtf8('order-id=INV-1001');
  final plain = toUtf8('Ship 3 units to dock-7');

  final aes = AES(key).gcm(nonce, aad: aad);
  final sealed = aes.encrypt(plain);
  final opened = aes.decrypt(sealed);

  print('AES-256-GCM');
  print('key   : ${toHex(key)}');
  print('nonce : ${toHex(nonce)}');
  print('aad   : ${fromUtf8(aad)}');
  print('cipher: ${toHex(sealed)}');
  print('plain : ${fromUtf8(opened)}');
}
