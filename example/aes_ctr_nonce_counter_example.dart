import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

void main() {
  final key = randomBytes(32);
  final nonce = Nonce64.random();
  final counter = Nonce64.int64(1);
  final plain = toUtf8('Chunk #1');

  final ctr = AESInCTRMode.iv(
    key,
    nonce: nonce,
    counter: counter,
  );

  final cipher = ctr.encrypt(plain);
  final opened = ctr.decrypt(cipher);

  print('AES-CTR with explicit nonce/counter');
  print('key     : ${toHex(key)}');
  print('nonce64 : ${nonce.hex()}');
  print('counter : ${counter.hex()}');
  print('cipher  : ${toHex(cipher)}');
  print('plain   : ${fromUtf8(opened)}');
}
