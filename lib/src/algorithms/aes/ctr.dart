// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/src/algorithms/aes/_core.dart';
import 'package:hashlib/hashlib.dart';

/// The sink used for both encryption and decryption by the [AESInCTRModeEncrypt] algorithm.
class AESInCTRModeSink extends CipherSink {
  AESInCTRModeSink(
    this._key, {
    required Uint8List nonce,
    required Uint8List counter,
  }) {
    if (nonce.length != 8) {
      throw ArgumentError('Nonce must be 8 bytes');
    }
    if (counter.length != 8) {
      throw ArgumentError('Counter must be 8 bytes');
    }
    int i;
    for (i = 0; i < 8; ++i) {
      _iv[i] = nonce[i];
    }
    for (i = 8; i < 16; ++i) {
      _iv[i] = counter[i - 8];
    }
  }

  int _pos = 0;
  bool _closed = false;
  final Uint8List _key;
  late final Uint32List _key32 = Uint32List.view(_key.buffer);
  final _iv = Uint8List(16);
  final _block = Uint8List(16); // 128-bit
  late final _block32 = Uint32List.view(_block.buffer);
  late final _xkey32 = AESCore.$expandEncryptionKey(_key32);

  @override
  Uint8List add(List<int> data, [bool last = false]) {
    if (_closed) {
      throw StateError('The sink is closed');
    }
    _closed = last;

    int i, j;
    var output = Uint8List(data.length);
    for (i = 0; i < data.length; ++i) {
      if (_pos == 0) {
        for (j = 0; j < 16; ++j) {
          _block[j] = _iv[j];
        }
        for (j = 15; j >= 8 && _iv[j]++ == 0; j--) {
          // adds 1 to the counter
        }
        AESCore.$encrypt(_block32, _xkey32);
      }
      output[i] = _block[_pos++] ^ data[i];
      if (_pos == 16) {
        _pos = 0;
      }
    }

    return output;
  }
}

/// Provides encryption for AES cipher in CTR mode.
class AESInCTRModeEncrypt extends SaltedCipher {
  @override
  String get name => "AES#encrypt/CTR";

  /// Key for the cipher
  final Uint8List key;

  /// The initial counter value
  final Uint8List counter;

  const AESInCTRModeEncrypt._(
    this.key, {
    required this.counter,
    required Uint8List nonce,
  }) : super(nonce);

  factory AESInCTRModeEncrypt(
    Uint8List key, {
    Int64? nonce,
    Int64? counter,
  }) =>
      AESInCTRModeEncrypt._(
        key,
        nonce: nonce?.bytes ?? randomBytes(8),
        counter: counter?.bytes ?? Uint8List(8),
      );

  @override
  @pragma('vm:prefer-inline')
  AESInCTRModeSink createSink() => AESInCTRModeSink(
        key,
        nonce: salt,
        counter: counter,
      );
}

/// Provides decryption for AES cipher in CTR mode.
class AESInCTRModeDecrypt extends SaltedCipher {
  @override
  String get name => "AES#decrypt/CTR";

  /// Key for the cipher
  final Uint8List key;

  /// The initial counter value
  final Uint8List counter;

  const AESInCTRModeDecrypt._(
    this.key, {
    required this.counter,
    required Uint8List nonce,
  }) : super(nonce);

  factory AESInCTRModeDecrypt(
    Uint8List key, {
    Int64? nonce,
    Int64? counter,
    Padding padding = Padding.pkcs7,
  }) =>
      AESInCTRModeDecrypt._(
        key,
        nonce: nonce?.bytes ?? randomBytes(8),
        counter: counter?.bytes ?? Uint8List(8),
      );

  @override
  @pragma('vm:prefer-inline')
  AESInCTRModeSink createSink() => AESInCTRModeSink(
        key,
        nonce: salt,
        counter: counter,
      );
}

/// Provides encryption and decryption for AES cipher in CTR mode.
class AESInCTRMode extends CollateCipher {
  @override
  String get name => "AES/CTR";

  @override
  final AESInCTRModeEncrypt encryptor;

  @override
  final AESInCTRModeDecrypt decryptor;

  const AESInCTRMode._({
    required this.encryptor,
    required this.decryptor,
  });

  /// Creates a AES cipher in CTR mode using a nonce and counter.
  ///
  /// Parameters:
  /// - [key] The key for encryption and decryption
  /// - [padding] The padding scheme for the messages
  /// - [nonce] 64-bit random nonce value.
  /// - [counter] 64-bit initial counter value.
  factory AESInCTRMode(
    List<int> key, {
    Int64? nonce,
    Int64? counter,
    Padding padding = Padding.pkcs7,
  }) {
    var nonce8 = nonce?.bytes ?? randomBytes(8);
    var counter8 = counter?.bytes ?? Uint8List(8);
    var key8 = key is Uint8List ? key : Uint8List.fromList(key);
    return AESInCTRMode._(
      encryptor: AESInCTRModeEncrypt._(
        key8,
        nonce: nonce8,
        counter: counter8,
      ),
      decryptor: AESInCTRModeDecrypt._(
        key8,
        nonce: nonce8,
        counter: counter8,
      ),
    );
  }

  /// Nonce for the cipher
  Int64 get nonce => Int64(encryptor.salt);

  /// Counter for the cipher
  Int64 get counter => Int64(encryptor.counter);

  /// Sets a random nonce value
  @pragma('vm:prefer-inline')
  void resetNonce() {
    fillRandom(nonce.bytes.buffer);
  }

  /// Sets the counter to 0
  @pragma('vm:prefer-inline')
  void resetCounter() {
    counter.bytes.fillRange(0, 8, 0);
  }
}
