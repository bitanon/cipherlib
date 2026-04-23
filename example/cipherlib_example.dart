import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  aesGcmExample();
  chacha20Poly1305Example();
  xchacha20Poly1305Example();
  tamperedMessageExample();
}

void aesGcmExample() {
  print('----- AES-256-GCM (recommended for most apps) -----');
  final plain = toUtf8('A practical message payload');
  final key = randomBytes(32);
  final nonce = randomBytes(12);
  final aad = toUtf8('request-id=42');

  final aes = AES(key).gcm(nonce, aad: aad);
  final sealed = aes.encrypt(plain);
  final opened = aes.decrypt(sealed);

  print('   Key: ${toHex(key)}');
  print(' Nonce: ${toHex(nonce)}');
  print('   AAD: ${fromUtf8(aad)}');
  print('Cipher: ${toHex(sealed)}');
  print(' Plain: ${fromUtf8(opened)}');
  print('');
}

void chacha20Poly1305Example() {
  print('----- ChaCha20-Poly1305 (mobile/network friendly) -----');
  final text = 'Hide me with ChaCha20';
  final key = randomBytes(32);
  final nonce = randomBytes(12);
  final aad = toUtf8('content-type:text');

  final sealed = chacha20poly1305(
    toUtf8(text),
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

  print('  Text: $text');
  print('   Key: ${toHex(key)}');
  print(' Nonce: ${toHex(nonce)}');
  print('Cipher: ${toHex(sealed.data)}');
  print('   Tag: ${sealed.mac.hex()}');
  print(' Plain: ${fromUtf8(opened.data)}');
  print('');
}

void xchacha20Poly1305Example() {
  print('----- XChaCha20-Poly1305 (extended nonce) -----');
  final text = 'Hide me!';
  final key = randomBytes(32);
  final nonce = randomBytes(24);

  final sealed = xchacha20poly1305(
    toUtf8(text),
    key,
    nonce: nonce,
    aad: toUtf8('demo-aad'),
  );
  final opened = xchacha20poly1305(
    sealed.data,
    key,
    nonce: nonce,
    aad: toUtf8('demo-aad'),
    mac: sealed.mac.bytes,
  );

  print('  Text: $text');
  print('   Key: ${toHex(key)}');
  print(' Nonce: ${toHex(nonce)}');
  print('Cipher: ${toHex(sealed.data)}');
  print('   Tag: ${sealed.mac.hex()}');
  print(' Plain: ${fromUtf8(opened.data)}');
  print('');
}

void tamperedMessageExample() {
  print('----- Tamper detection -----');
  final key = randomBytes(32);
  final nonce = randomBytes(24);
  final sealed = xchacha20poly1305(
    toUtf8('integrity protected'),
    key,
    nonce: nonce,
  );
  final badTag = List<int>.from(sealed.mac.bytes)..[0] ^= 0xff;

  try {
    xchacha20poly1305(
      sealed.data,
      key,
      nonce: nonce,
      mac: badTag,
    );
    print('Unexpected: tampered message accepted');
  } on StateError catch (e) {
    print('Rejected tampered message: ${e.message}');
  }
  print('');
}
