// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show HashDigest, MACHashBase;

import '../core/cipher.dart';

/// The result from AEAD ciphers
class AEADResult {
  /// The output message
  final Uint8List data;

  /// The message authentication code
  final HashDigest mac;

  const AEADResult._(this.data, this.mac);

  /// Returns whether the generated [mac] (message authentication code) is
  /// equal to the provided tag [digest].
  bool verify(List<int>? digest) => mac.isEqual(digest);

  /// Creates a new instance of AEADResult with IV parameter
  AEADResultWithIV withIV(Uint8List iv) => AEADResultWithIV._(data, mac, iv);
}

/// The result from AEAD ciphers having an IV or nonce
class AEADResultWithIV extends AEADResult {
  /// The nonce or initialization vector
  final Uint8List iv;

  const AEADResultWithIV._(
    super.data,
    super.mac,
    this.iv,
  ) : super._();
}

/// Provides support for AEAD (Authenticated Encryption with Associated Data) to
/// the any [Cipher] with any MAC algorithm.
class AEADCipher<C extends Cipher, M extends MACHashBase> implements Cipher {
  /// The MAC generator used by this AEAD construction
  final M algo;

  /// The cipher used by this AEAD construction
  final C cipher;

  @override
  String get name => '${cipher.name}/${algo.name}';

  /// Creates a new instance of [AEADCipher] with the given [cipher] and [algo].
  ///
  /// Parameters:
  /// - [cipher] : The cipher used by this AEAD construction.
  /// - [algo] : The MAC generator used by this AEAD construction.
  const AEADCipher(this.cipher, this.algo);

  /// Transforms the [message] of bytes using the [cipher] algorithm without
  /// generating a message authentication code.
  @override
  @pragma('vm:prefer-inline')
  Uint8List convert(List<int> message) => cipher.convert(message);

  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  static Uint8List _build128(int high, int low) => Uint8List.fromList([
        low,
        low >>> 8,
        low >>> 16,
        low >>> 24,
        low >>> 32,
        low >>> 40,
        low >>> 48,
        low >>> 56,
        high,
        high >>> 8,
        high >>> 16,
        high >>> 24,
        high >>> 32,
        high >>> 40,
        high >>> 48,
        high >>> 56,
      ]);

  /// Generates a message authentication code for the [data].
  HashDigest $mac(List<int> data, [List<int>? aad]) {
    int aadLength = 0;
    int dataLength = data.length;
    final sink = algo.createSink();

    if (aad != null) {
      aadLength = aad.length;
      sink.add(aad);
      if (aadLength & 15 != 0) {
        sink.add(Uint8List(16 - (aadLength & 15))); // pad with zero
      }
    }

    sink.add(data);
    if (dataLength & 15 != 0) {
      sink.add(Uint8List(16 - (dataLength & 15))); // pad with zero
    }

    sink.add(_build128(dataLength, aadLength));

    sink.close();
    return sink.digest();
  }

  /// Signs the [message] with an authentication tag.
  ///
  /// Parameters:
  /// - [message] : The message to sign.
  /// - [aad] : Additional authenticated data (optional).
  AEADResult sign(List<int> message, [List<int>? aad]) {
    final output = cipher.convert(message);
    return AEADResult._(output, $mac(output, aad));
  }

  /// Returns true if input [message] can be verified by the given message
  /// authentication code [mac].
  @pragma('vm:prefer-inline')
  bool verify(List<int> message, List<int> mac, [List<int>? aad]) {
    return $mac(message, aad).isEqual(mac);
  }
}
