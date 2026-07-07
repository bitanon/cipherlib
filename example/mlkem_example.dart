import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';

void main() {
  final kem = MLKEM.kem768();

  // Alice generates a key pair and publishes the encapsulation key
  final alice = kem.keygen();

  // Bob encapsulates a shared secret with Alice's public key and
  // transmits the ciphertext back to Alice
  final bob = kem.encaps(alice.encapsulationKey);

  // Alice recovers the same shared secret from the ciphertext
  final shared = kem.decaps(alice.decapsulationKey, bob.cipherText);

  print(kem.name);
  print('bob   : ${bob.sharedSecret.hex()}');
  print('alice : ${shared.hex()}');
  print('match : ${shared.isEqual(bob.sharedSecret)}');

  // A key pair can be stored as its 64-byte seed and re-derived later
  final seed = List.generate(64, (i) => i);
  final first = kem.keygen(seed: seed);
  final again = kem.keygen(seed: seed);
  final isSeeded =
      toHex(first.encapsulationKey) == toHex(again.encapsulationKey);
  print('seeded: $isSeeded');
}
