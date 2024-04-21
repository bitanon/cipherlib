import 'dart:typed_data';

import 'package:cipherlib/src/core/cipher_base.dart';

/// Template for stream cipher (i.e. ChaCha20)
abstract class StreamCipher extends SymmetricCipher<Uint8List, Stream<int>> {
  //
}

/// Template for block cipher (i.e. AES)
abstract class BlockCipher extends StreamCipher {
  //
}
