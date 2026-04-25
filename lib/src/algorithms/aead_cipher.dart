// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:hashlib/hashlib.dart'
    show HashDigest, HashDigestSink, MACHashBase;

import '../core/cipher.dart';

// ------------------------------------------------------------
// AEADCipher & Related Classes
// ------------------------------------------------------------

/// Provides support for AEAD (Authenticated Encryption with Associated Data) to
/// the any [Cipher] with any MAC algorithm.
class AEADCipher<C extends Cipher, M extends MACHashBase> implements Cipher {
  @override
  String get name => '${cipher.name}/${algo.name}';

  /// The MAC generator used by this AEAD construction
  final M algo;

  /// The cipher used by this AEAD construction
  final C cipher;

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
  @pragma('dart2js:tryInline')
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

  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  HashDigestSink _createSink(List<int>? aad) {
    final sink = algo.createSink();

    if (aad != null) {
      sink.add(aad);
      if (aad.length & 15 != 0) {
        sink.add(Uint8List(16 - (aad.length & 15))); // pad with zero
      }
    }

    return sink;
  }

  /// Generates a message authentication code for the [data].
  HashDigest $mac(List<int> data, [List<int>? aad]) {
    int dataLength = data.length;
    int aadLength = aad?.length ?? 0;
    final sink = _createSink(aad);

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
  @pragma('vm:prefer-inline')
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

/// The result from AEAD ciphers
class AEADResult {
  const AEADResult._(this.data, this.mac);

  /// The output message
  final Uint8List data;

  /// The message authentication code
  final HashDigest mac;

  /// Returns true if the generated [mac] (message authentication code) is
  /// equal to the provided tag [tag], otherwise false.
  bool verify(List<int> tag) => mac.isEqual(tag);

  /// Creates a new instance of [AEADResult] with IV parameter
  AEADResultWithIV withIV(Uint8List iv) => AEADResultWithIV._(data, mac, iv);
}

/// The result from AEAD ciphers having an IV or nonce
class AEADResultWithIV extends AEADResult {
  const AEADResultWithIV._(
    super.data,
    super.mac,
    this.iv,
  ) : super._();

  /// The nonce or initialization vector
  final Uint8List iv;
}

// ------------------------------------------------------------
// AEADStreamCipher & Related Classes
// ------------------------------------------------------------

class AEADStreamCipher<C extends StreamCipher, M extends MACHashBase>
    extends AEADCipher<C, M> implements StreamCipher {
  const AEADStreamCipher(super.cipher, super.algo);

  @override
  @pragma('vm:prefer-inline')
  Stream<Uint8List> bind(Stream<List<int>> stream) => cipher.bind(stream);

  @override
  StreamTransformer<RS, RT> cast<RS, RT>() {
    throw UnsupportedError('AEADCipher does not allow casting');
  }

  /// Generates a message authentication tag for a [stream] of data.
  ///
  /// Parameters:
  /// - [stream] : The stream of data to encrypt.
  /// - [aad] : Additional authenticated data (optional).
  AEADStreamResult signStream(
    Stream<List<int>> stream, [
    List<int>? aad,
  ]) {
    final digest = Completer<HashDigest>();
    final output = StreamController<Uint8List>();
    late final StreamSubscription<Uint8List> subscription;

    output.onListen = () {
      int dataLength = 0;
      int aadLength = aad?.length ?? 0;
      final sink = _createSink(aad);
      subscription = cipher.bind(stream).listen(
        (data) {
          dataLength += data.length;
          sink.add(data);
          output.add(data);
        },
        onDone: () {
          if (dataLength & 15 != 0) {
            sink.add(Uint8List(16 - (dataLength & 15))); // pad with zero
          }
          sink.add(AEADCipher._build128(dataLength, aadLength));
          sink.close();
          if (!digest.isCompleted) {
            digest.complete(sink.digest());
          }
          output.close();
        },
        onError: (Object error, StackTrace stackTrace) {
          if (!digest.isCompleted) {
            digest.completeError(error, stackTrace);
          }
          output.addError(error, stackTrace);
        },
      );
    };
    output.onPause = () => subscription.pause();
    output.onResume = () => subscription.resume();
    output.onCancel = () => subscription.cancel();

    return AEADStreamResult._(output.stream, digest.future);
  }

  /// Returns true if input [stream] can be verified by the given message
  /// authentication tag [mac].
  Future<bool> verifyStream(
    Stream<List<int>> stream,
    List<int> mac, [
    List<int>? aad,
  ]) async {
    int dataLength = 0;
    int aadLength = aad?.length ?? 0;
    final sink = _createSink(aad);

    await for (var data in stream) {
      dataLength += data.length;
      sink.add(data);
    }
    if (dataLength & 15 != 0) {
      sink.add(Uint8List(16 - (dataLength & 15))); // pad with zero
    }

    sink.add(AEADCipher._build128(dataLength, aadLength));

    sink.close();
    return sink.digest().isEqual(mac);
  }
}

/// The result from AEAD stream ciphers
class AEADStreamResult extends Stream<Uint8List> {
  final Stream<Uint8List> _stream;
  AEADStreamResult._(this._stream, this.mac);

  /// The message authentication code.
  ///
  /// If there is no listener on this stream, or the listener pauses and never
  /// resumes, the done event will not be sent and this future will never complete.
  final Future<HashDigest> mac;

  /// Returns true if the generated [mac] (message authentication code) is
  /// equal to the provided tag [tag], otherwise false.
  Future<bool> verify(List<int> tag) async => (await mac).isEqual(tag);

  /// Creates a new instance of [AEADStreamResult] with IV parameter
  AEADStreamResultWithIV withIV(Uint8List iv) =>
      AEADStreamResultWithIV._(_stream, mac, iv);

  @override
  @pragma('vm:prefer-inline')
  @pragma('dart2js:tryInline')
  StreamSubscription<Uint8List> listen(
    void Function(Uint8List event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) =>
      _stream.listen(
        onData,
        onError: onError,
        onDone: onDone,
        cancelOnError: cancelOnError,
      );
}

/// The result from AEAD stream ciphers having an IV or nonce
class AEADStreamResultWithIV extends AEADStreamResult {
  AEADStreamResultWithIV._(super._stream, super._mac, this.iv) : super._();

  /// The nonce or initialization vector
  final Uint8List iv;
}
