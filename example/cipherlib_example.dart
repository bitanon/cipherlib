import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/hashlib.dart';
import 'package:hashlib/codecs.dart';

void main() {
  print('----- AES -----');
  {
    var plain = 'A not very secret message';
    var key = randomBytes(32);
    var iv = randomBytes(16);
    print('  Text: $plain');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(iv)}');
    // different modes
    print('  ECB: ${toHex(AES(key).ecb().encryptString(plain))}');
    print('  CBC: ${toHex(AES(key).cbc(iv).encryptString(plain))}');
    print('  CTR: ${toHex(AES(key).ctr(iv).encryptString(plain))}');
    print('  GCM: ${toHex(AES(key).gcm(iv).encryptString(plain))}');
    print('  CFB: ${toHex(AES(key).cfb(iv).encryptString(plain))}');
    print('  OFB: ${toHex(AES(key).ofb(iv).encryptString(plain))}');
    print('  XTS: ${toHex(AES(key).xts(iv).encryptString(plain))}');
    print('  IGE: ${toHex(AES(key).ige(iv).encryptString(plain))}');
    print(' PCBC: ${toHex(AES(key).pcbc(iv).encryptString(plain))}');
  }
  print('');

  print('----- XChaCha20 -----');
  {
    var text = "Hide me!";
    var key = randomBytes(32);
    var nonce = randomBytes(24);
    // encrypt and sign
    var cipher = xchacha20poly1305(
      toUtf8(text),
      key,
      nonce: nonce,
    );
    // verify and decrypt
    var plain = xchacha20poly1305(
      cipher.data,
      key,
      nonce: nonce,
      mac: cipher.tag.bytes,
    );
    print('  Text: $text');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(nonce)}');
    print('Cipher: ${toHex(cipher.data)}');
    print('   Tag: ${cipher.tag.hex()}');
    print(' Plain: ${fromUtf8(plain.data)}');
  }
  print('');
}
