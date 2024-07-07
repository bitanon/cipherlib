import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';

void main() {
  print('----- AES -----');
  {
    var plain = 'A not very secret message';
    var key = 'abcdefghijklmnop'.codeUnits;
    var iv = 'lka9JLKasljkdPsd'.codeUnits;
    print('  Text: $plain');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(iv)}');
    print('  ECB: ${toHex(AES(key).ecb().encryptString(plain))}');
    print('  CBC: ${toHex(AES(key).cbc(iv).encryptString(plain))}');
    print(' PCBC: ${toHex(AES(key).pcbc(iv).encryptString(plain))}');
    print('  CTR: ${toHex(AES(key).ctr(iv).encryptString(plain))}');
    print('  CFB: ${toHex(AES(key).cfb(iv).encryptString(plain))}');
    print('  OFB: ${toHex(AES(key).ofb(iv).encryptString(plain))}');
  }
  print('');

  print('----- XOR -----');
  {
    var key = [0x54];
    var inp = [0x03, 0xF1];
    var cipher = xor(inp, key);
    var plain = xor(cipher, key);
    print('  Text: ${toBinary(inp)}');
    print('   Key: ${toBinary(key)}');
    print('   XOR: ${toBinary(cipher)}');
    print(' Plain: ${toBinary(plain)}');
  }
  print('');

  print('----- ChaCha20 -----');
  {
    var text = "Hide me!";
    var key = fromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    var nonce = fromHex("00000000000000004a000000");
    var res = chacha20poly1305(toUtf8(text), key, nonce: nonce);
    var plain = chacha20(res.message, key, nonce: nonce);
    print('  Text: $text');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(nonce)}');
    print('Cipher: ${toHex(res.message)}');
    print('   Tag: ${res.mac.hex()}');
    print(' Plain: ${fromUtf8(plain)}');
  }
  print('');

  print('----- Salsa20 -----');
  {
    var text = "Hide me!";
    var key = fromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    var nonce = fromHex("00000000000000004a00000000000000");
    var res = salsa20poly1305(toUtf8(text), key, nonce: nonce);
    var plain = salsa20(res.message, key, nonce: nonce);
    print('  Text: $text');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(nonce)}');
    print('Cipher: ${toHex(res.message)}');
    print('   Tag: ${res.mac.hex()}');
    print(' Plain: ${fromUtf8(plain)}');
  }
}
