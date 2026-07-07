// Cipherlib examples: authenticated encryption, tamper detection, and
// post-quantum key exchange.
//
// Each AEAD example encrypts a short message, decrypts it back, and verifies
// the round-trip. The tamper example shows how a modified ciphertext is
// rejected, and the ML-KEM example performs a post-quantum key exchange.
//
// Run with: dart run example/cipherlib_example.dart

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  mlkemExample();
  aesGcmExample();
  chacha20Poly1305Example();
  xchacha20Poly1305Example();
  tamperedMessageExample();
}

// ML-KEM (FIPS 203) post-quantum key encapsulation: Alice publishes an
// encapsulation key; Bob derives a shared secret and a ciphertext from it;
// Alice recovers the same secret from that ciphertext.
void mlkemExample() {
  print('----- ML-KEM-768 (post-quantum key exchange) -----');
  final kem = MLKEM.kem768();

  final alice = kem.keygen(); // Alice's key pair
  final bob = kem.encaps(alice.encapsulationKey); // Bob encapsulates a secret
  final shared = kem.decaps(alice.decapsulationKey, bob.cipherText);

  print('   Bob: ${bob.sharedSecret.hex()}');
  print(' Alice: ${shared.hex()}');
  // Compare shared secrets in constant time, not with `==`.
  print(' Match: ${shared.isEqual(bob.sharedSecret)}');
  print('');
}

// AES-256-GCM via the object API: build a cipher instance, then encrypt and
// decrypt with it. A solid default for most applications.
void aesGcmExample() {
  print('----- AES-256-GCM (recommended for most apps) -----');
  final text = 'A practical message payload';
  final key = randomBytes(32); // 256-bit key
  final nonce = randomBytes(12); // fresh per message; never reuse (key, nonce)
  final aad = toUtf8('request-id=42'); // authenticated, but not encrypted

  final aes = AES(key).gcm(nonce, aad: aad);
  final sealed = aes.encrypt(toUtf8(text));
  final opened = aes.decrypt(sealed);

  print('   Key: ${toHex(key)}');
  print(' Nonce: ${toHex(nonce)}');
  print('   AAD: ${fromUtf8(aad)}');
  print('Cipher: ${toHex(sealed)}');
  print(' Plain: ${fromUtf8(opened)}');
  print(' Match: ${fromUtf8(opened) == text}');
  print('');
}

// ChaCha20-Poly1305 via the one-shot function API: the result carries both the
// ciphertext (`.data`) and the authentication tag (`.mac`).
void chacha20Poly1305Example() {
  print('----- ChaCha20-Poly1305 (mobile/network friendly) -----');
  final text = 'Hide me with ChaCha20';
  final key = randomBytes(32);
  final nonce = randomBytes(12); // fresh per message; never reuse (key, nonce)
  final aad = toUtf8('content-type:text');

  final sealed = chacha20poly1305(
    toUtf8(text),
    key,
    nonce: nonce,
    aad: aad,
  );
  // Decrypt by passing the tag back in via `mac:`; a mismatch throws.
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
  print(' Match: ${fromUtf8(opened.data) == text}');
  print('');
}

// XChaCha20-Poly1305 takes a 24-byte nonce — large enough to choose at random
// for every message without worrying about the birthday bound.
void xchacha20Poly1305Example() {
  print('----- XChaCha20-Poly1305 (extended nonce) -----');
  final text = 'Hide me!';
  final key = randomBytes(32);
  final nonce = randomBytes(24); // 192-bit nonce; safe to randomize per message
  final aad = toUtf8('demo-aad');

  final sealed = xchacha20poly1305(
    toUtf8(text),
    key,
    nonce: nonce,
    aad: aad,
  );
  final opened = xchacha20poly1305(
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
  print(' Match: ${fromUtf8(opened.data) == text}');
  print('');
}

// Flipping a single tag bit makes decryption fail: authenticated ciphers
// reject tampered input instead of returning corrupted plaintext.
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
