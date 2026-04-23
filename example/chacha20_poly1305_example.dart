import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(32);
  final nonce = randomBytes(12);
  final aad = toUtf8('content-type=application/json');
  final message = toUtf8('{"event":"payment.settled","id":42}');

  final sealed = chacha20poly1305(
    message,
    key,
    nonce: nonce,
    aad: aad,
  );

  final opened = chacha20poly1305(
    sealed.data,
    key,
    nonce: nonce,
    aad: aad,
    mac: sealed.mac.bytes,
  );

  print('ChaCha20-Poly1305');
  print('key   : ${toHex(key)}');
  print('nonce : ${toHex(nonce)}');
  print('tag   : ${sealed.mac.hex()}');
  print('cipher: ${toHex(sealed.data)}');
  print('plain : ${fromUtf8(opened.data)}');
}
