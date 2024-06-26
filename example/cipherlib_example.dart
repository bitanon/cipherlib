import 'dart:convert';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';

void main() {
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

  print('----- ChaCha20 -----');
  {
    var text = "Hide me!";
    var key = fromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    var nonce = fromHex("000000000000004a00000000");
    var result = chacha20poly1305(utf8.encode(text), key, nonce: nonce);
    var plain = chacha20poly1305(
      result.cipher,
      key,
      nonce: nonce,
      mac: result.mac.bytes,
    );
    print('  Text: $text');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(nonce)}');
    print('Cipher: ${toHex(result.cipher)}');
    print('   Tag: ${result.mac.hex()}');
    print(' Plain: ${utf8.decode(plain.cipher)}');
  }
}
