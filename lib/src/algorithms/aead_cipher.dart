// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
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

  /// Additional authenticated data (optional)
  final List<int>? aad;

  @override
  String get name => '${cipher.name}/${algo.name}';

  const AEADCipher(
    this.cipher,
    this.algo, [
    this.aad,
  ]);

  /// Generates a message authentication code for the [data].
  HashDigest generateMAC(List<int> data) {
    int aadLength = 0;
    int dataLength = data.length;
    final sink = algo.createSink();

    if (aad != null) {
      aadLength = aad!.length;
      sink.add(aad!);
      if (aadLength & 15 != 0) {
        sink.add(Uint8List(16 - (aadLength & 15))); // pad with zero
      }
    }

    sink.add(data);
    if (dataLength & 15 != 0) {
      sink.add(Uint8List(16 - (dataLength & 15))); // pad with zero
    }

    sink.add([
      aadLength,
      aadLength >>> 8,
      aadLength >>> 16,
      aadLength >>> 24,
      aadLength >>> 32,
      aadLength >>> 40,
      aadLength >>> 48,
      aadLength >>> 56,
      dataLength,
      dataLength >>> 8,
      dataLength >>> 16,
      dataLength >>> 24,
      dataLength >>> 32,
      dataLength >>> 40,
      dataLength >>> 48,
      dataLength >>> 56,
    ]);

    sink.close();
    return sink.digest();
  }

  /// Signs the [message] with an authentication tag.
  AEADResult sign(List<int> message) {
    final output = cipher.convert(message);
    return AEADResult._(output, generateMAC(output));
  }

  /// Returns true if input [message] can be verified by the given message
  /// authentication code [mac].
  @pragma('vm:prefer-inline')
  bool verify(List<int> message, List<int> mac) {
    return generateMAC(message).isEqual(mac);
  }

  @override
  @pragma('vm:prefer-inline')
  Uint8List convert(List<int> message) => cipher.convert(message);

  @override
  @pragma('vm:prefer-inline')
  Stream<Uint8List> bind(Stream<List<int>> stream) =>
      stream.map(cipher.convert);

  @override
  @pragma('vm:prefer-inline')
  Stream<int> stream(Stream<int> stream, [int chunkSize = 1024]) =>
      cipher.stream(stream, chunkSize);

  @override
  StreamTransformer<RS, RT> cast<RS, RT>() {
    throw UnsupportedError('AEADCipher does not allow casting');
  }
}
