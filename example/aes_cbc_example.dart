import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(32);
  final iv = randomBytes(16);
  final plain = 'Confidential invoice payload';

  // PKCS7 is the common padding choice for block modes like CBC.
  final cbc = AES.pkcs7(key).cbc(iv);
  final cipher = cbc.encryptString(plain);
  final opened = cbc.decrypt(cipher);

  print('AES-256-CBC + PKCS7');
  print('key   : ${toHex(key)}');
  print('iv    : ${toHex(iv)}');
  print('cipher: ${toHex(cipher)}');
  print('plain : ${fromUtf8(opened)}');
}
