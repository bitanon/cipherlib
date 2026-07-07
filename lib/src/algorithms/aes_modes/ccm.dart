// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/random.dart' show randomBytes;

import '../../core/aes.dart';
import '../../core/cipher.dart';
import '../../utils/typed_data.dart';
import '../padding.dart';

/// This implementation is derived from [RFC 3610 - Counter with CBC-MAC][rfc].
///
/// [rfc]: https://datatracker.ietf.org/doc/html/rfc3610
class AESInCCMModeCipherCore {
  final Uint8List key;
  final Uint8List nonce;
  final Uint8List? aad;
  final int tagSize;

  AESInCCMModeCipherCore(
    this.key,
    this.nonce,
    this.aad,
    this.tagSize,
  );

  final x32 = Uint32List(4); // the CBC-MAC state
  final block32 = Uint32List(4); // 128-bit scratch block

  late final x = Uint8List.view(x32.buffer);
  late final block = Uint8List.view(block32.buffer);
  late final xkey32 = AESCore.$expandEncryptionKey(Uint32List.view(key.buffer));

  /// Number of octets in the length field: `L = 15 - l(nonce)`
  @pragma('vm:prefer-inline')
  int get _lSize => 15 - nonce.length;

  /// Message length limit: `2^(8 * L)`
  @pragma('vm:prefer-inline')
  BigInt get _maxMessageSize => BigInt.one << (8 * _lSize);

  /// Absorbs the scratch block into the CBC-MAC state: `X_i+1 = E(X_i ^ B_i)`
  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  void _updateMAC() {
    x32[0] ^= block32[0];
    x32[1] ^= block32[1];
    x32[2] ^= block32[2];
    x32[3] ^= block32[3];
    AESCore.$encryptLE(x32, xkey32);
  }

  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  static void _encodeLength(Uint8List out, int offset, int value, int length) {
    for (int i = 0; i < length; ++i) {
      out[offset + length - 1 - i] = value & 0xFF;
      value >>= 8;
    }
  }

  /// Builds the counter block `A_i` and puts its keystream `S_i` into the
  /// scratch block: `S_i = E(A_i)`
  @pragma('vm:prefer-inline')
  void _buildKeystreamBlock(int counter) {
    block[0] = _lSize - 1;
    block.setRange(1, 1 + nonce.length, nonce);
    _encodeLength(block, 16 - _lSize, counter, _lSize);
    AESCore.$encryptLE(block32, xkey32);
  }

  /// Computes the CBC-MAC tag `T` of the [message] into [x]
  void _computeTag(List<int> message) {
    int i, n, pos;
    final hasAad = aad != null && aad!.isNotEmpty;

    x32[0] = x32[1] = x32[2] = x32[3] = 0;

    // the first block B_0: flags | nonce | l(m)
    block[0] =
        (hasAad ? 0x40 : 0x00) | (((tagSize - 2) ~/ 2) << 3) | (_lSize - 1);
    block.setRange(1, 1 + nonce.length, nonce);
    _encodeLength(block, 16 - _lSize, message.length, _lSize);
    _updateMAC();

    // the blocks encoding l(a) followed by the additional data
    if (hasAad) {
      final a = aad!;
      block32[0] = block32[1] = block32[2] = block32[3] = 0;
      if (a.length < 0xFF00) {
        block[0] = a.length >>> 8;
        block[1] = a.length & 0xFF;
        i = 2;
      } else if (a.length < 0x100000000) {
        block[0] = 0xFF;
        block[1] = 0xFE;
        _encodeLength(block, 2, a.length, 4);
        i = 6;
      } else {
        throw StateError('Additional authenticated data is too large');
      }

      pos = 0;
      while (i < 16 && pos < a.length) {
        block[i++] = a[pos++];
      }
      _updateMAC();

      while (pos < a.length) {
        block32[0] = block32[1] = block32[2] = block32[3] = 0;
        n = (a.length - pos) > 16 ? 16 : (a.length - pos);
        block.setRange(0, n, a, pos);
        pos += n;
        _updateMAC();
      }
    }

    // the message blocks
    pos = 0;
    while (pos < message.length) {
      block32[0] = block32[1] = block32[2] = block32[3] = 0;
      n = (message.length - pos) > 16 ? 16 : (message.length - pos);
      for (i = 0; i < n; ++i) {
        block[i] = message[pos + i];
      }
      pos += n;
      _updateMAC();
    }
  }

  /// XORs the [message] into [output] with the CTR keystream `S_1, S_2, ...`
  void _cryptMessage(List<int> message, Uint8List output) {
    int i, n;
    int pos = 0;
    int counter = 1;
    while (pos < message.length) {
      _buildKeystreamBlock(counter++);
      n = (message.length - pos) > 16 ? 16 : (message.length - pos);
      for (i = 0; i < n; ++i) {
        output[pos + i] = message[pos + i] ^ block[i];
      }
      pos += n;
    }
  }

  Uint8List encrypt(List<int> message) {
    int i;
    final n = message.length;
    if (BigInt.from(n) >= _maxMessageSize) {
      throw StateError('Message is too large for nonce size');
    }
    final output = Uint8List(n + tagSize);

    // T = CBC-MAC of the message
    _computeTag(message);

    // seal the tag: U = T ^ S_0
    _buildKeystreamBlock(0);
    for (i = 0; i < tagSize; ++i) {
      output[n + i] = x[i] ^ block[i];
    }

    // encrypt the message: C_i = M_i ^ S_i
    _cryptMessage(message, output);
    return output;
  }

  Uint8List decrypt(List<int> message) {
    int i;
    final n = message.length - tagSize;
    if (n < 0) {
      throw StateError('Invalid message size');
    }
    if (BigInt.from(n) >= _maxMessageSize) {
      throw StateError('Message is too large for nonce size');
    }

    final input = toUint8List(message);
    final output = Uint8List(n);

    // decrypt the message: M_i = C_i ^ S_i
    _cryptMessage(Uint8List.sublistView(input, 0, n), output);

    // T = CBC-MAC of the recovered message
    _computeTag(output);

    // verify the tag: U = T ^ S_0
    _buildKeystreamBlock(0);
    bool valid = true;
    for (i = 0; i < tagSize; ++i) {
      if ((x[i] ^ block[i]) != input[n + i]) {
        valid = false;
      }
    }
    if (!valid) {
      throw StateError('Message authentication check failed');
    }
    return output;
  }
}

/// Provides AES cipher in CCM mode for encryption.
class AESInCCMModeEncrypt extends StreamCipher with SaltedCipher {
  @override
  String get name => "AES#encrypt/CCM/${Padding.none.name}";

  /// Key for the cipher
  final Uint8List key;

  @override
  final Uint8List iv;

  /// Additional authenticated data for AEAD construction
  final Uint8List? aad;

  /// The length of the message authentication tag in bytes
  final int tagSize;

  const AESInCCMModeEncrypt(
    this.key,
    this.iv, {
    this.aad,
    required this.tagSize,
  });

  @override
  Uint8List convert(List<int> message) {
    final core = AESInCCMModeCipherCore(key, iv, aad, tagSize);
    return core.encrypt(message);
  }

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) async* {
    final input = <int>[];
    await for (final chunk in stream) {
      input.addAll(chunk);
    }
    yield convert(input);
  }
}

/// Provides AES cipher in CCM mode for decryption.
class AESInCCMModeDecrypt extends StreamCipher with SaltedCipher {
  @override
  String get name => "AES#decrypt/CCM/${Padding.none.name}";

  /// Key for the cipher
  final Uint8List key;

  @override
  final Uint8List iv;

  /// Additional authenticated data for AEAD construction
  final Uint8List? aad;

  /// The length of the message authentication tag in bytes
  final int tagSize;

  const AESInCCMModeDecrypt(
    this.key,
    this.iv, {
    this.aad,
    required this.tagSize,
  });

  @override
  Uint8List convert(List<int> message) {
    final core = AESInCCMModeCipherCore(key, iv, aad, tagSize);
    return core.decrypt(message);
  }

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) async* {
    final input = <int>[];
    await for (final chunk in stream) {
      input.addAll(chunk);
    }
    yield convert(input);
  }
}

/// Provides encryption and decryption for AES cipher in CCM mode.
class AESInCCMMode extends StreamCipherPair with SaltedCipher {
  @override
  String get name => "AES/CCM/${Padding.none.name}";

  @override
  final AESInCCMModeEncrypt encryptor;

  @override
  final AESInCCMModeDecrypt decryptor;

  const AESInCCMMode._({
    required this.encryptor,
    required this.decryptor,
  });

  @override
  Uint8List get iv => encryptor.iv;

  /// Creates AES cipher in CCM mode.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [iv] A random nonce between 7 and 13 bytes (Default: 13 random bytes)
  /// - [aad] Additional authentication data for tag generation
  /// - [tagSize] The length of the message authentication tag in bytes.
  ///   It must be an even number between 4 and 16.
  factory AESInCCMMode(
    List<int> key, {
    List<int>? iv,
    Iterable<int>? aad,
    int tagSize = 16,
  }) {
    if (tagSize < 4 || tagSize > 16 || (tagSize & 1) == 1) {
      throw StateError('Tag size must be an even number between 4 and 16');
    }

    final key8 = toUint8List(key);
    if (key8.length != 16 && key8.length != 24 && key8.length != 32) {
      throw StateError('Key must be 16, 24, or 32 bytes');
    }

    iv ??= randomBytes(13);
    final iv8 = toUint8List(iv);
    if (iv8.length < 7 || iv8.length > 13) {
      throw StateError('Nonce must be between 7 and 13 bytes');
    }

    final aad8 = aad != null ? toUint8List(aad) : null;

    return AESInCCMMode._(
      encryptor: AESInCCMModeEncrypt(
        key8,
        iv8,
        aad: aad8,
        tagSize: tagSize,
      ),
      decryptor: AESInCCMModeDecrypt(
        key8,
        iv8,
        aad: aad8,
        tagSize: tagSize,
      ),
    );
  }
}
