// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:async';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/hashlib.dart';
import 'package:hashlib/random.dart';
import 'package:test/test.dart';

void main() {
  group('AEADCipher common behavior', () {
    test('convert delegates to wrapped cipher conversion', () {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final payload = randomBytes(37);
      final macKey = randomBytes(32);

      final wrapped = ChaCha20(key, nonce);
      final aead = AEADCipher(
        wrapped,
        Poly1305(Uint8List.fromList(macKey)),
      );

      expect(aead.convert(payload), equals(wrapped.convert(payload)));
    });

    test('AEADResult.withIV creates a result with provided nonce', () {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final payload = randomBytes(17);

      final signed = ChaCha20(key, nonce).poly1305().sign(payload);
      final customIv = Uint8List.fromList(List<int>.filled(24, 5));
      final withIv = signed.withIV(customIv);

      expect(withIv.data, equals(signed.data));
      expect(withIv.mac.bytes, equals(signed.mac.bytes));
      expect(withIv.iv, equals(customIv));
    });
  });

  group('AEADStreamCipher behavior', () {
    test('bind delegates to wrapped stream cipher', () async {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final payload = randomBytes(55);
      final macKey = randomBytes(32);

      final expected = ChaCha20(key, nonce)
          .bind(Stream<List<int>>.fromIterable([
            payload.sublist(0, 10),
            payload.sublist(10),
          ]))
          .expand((chunk) => chunk)
          .toList();

      final streamCipher = AEADStreamCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      );

      final actual = await streamCipher
          .bind(Stream<List<int>>.fromIterable([
            payload.sublist(0, 10),
            payload.sublist(10),
          ]))
          .expand((chunk) => chunk)
          .toList();

      expect(actual, equals(await expected));
    });

    test('signStream emits transformed data and mac for same stream', () async {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final aad = randomBytes(21);
      final payload = randomBytes(97);
      final macKey = randomBytes(32);

      final expected = AEADCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      ).sign(payload, aad);

      final streamCipher = AEADStreamCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      );

      final result = streamCipher.signStream(
        Stream<List<int>>.fromIterable([
          payload.sublist(0, 13),
          payload.sublist(13, 41),
          payload.sublist(41),
        ]),
        aad,
      );

      final output = await result.expand((chunk) => chunk).toList();
      expect(output, equals(expected.data));

      final tag = await result.mac;
      expect(tag.bytes, equals(expected.mac.bytes));

      expect(await result.verify(expected.mac.bytes), isTrue);
    });

    test('verifyStream validates tag for chunked ciphertext stream', () async {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final aad = randomBytes(33);
      final payload = randomBytes(64);
      final macKey = randomBytes(32);

      final signed = AEADCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      ).sign(payload, aad);

      final verifier = AEADStreamCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      );

      final isValid = await verifier.verifyStream(
        Stream<List<int>>.fromIterable([
          signed.data.sublist(0, 7),
          signed.data.sublist(7, 29),
          signed.data.sublist(29),
        ]),
        signed.mac.bytes,
        aad,
      );

      expect(isValid, isTrue);
    });

    test('verifyStream handles non-16-byte-aligned input lengths', () async {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final aad = randomBytes(5);
      final payload = randomBytes(31);
      final macKey = randomBytes(32);

      final signed = AEADCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      ).sign(payload, aad);

      final verifier = AEADStreamCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      );

      final isValid = await verifier.verifyStream(
        Stream<List<int>>.fromIterable([
          signed.data.sublist(0, 9),
          signed.data.sublist(9, 19),
          signed.data.sublist(19),
        ]),
        signed.mac.bytes,
        aad,
      );

      expect(isValid, isTrue);
    });

    test('verifyStream returns false for mismatched tag', () async {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final payload = randomBytes(48);
      final macKey = randomBytes(32);

      final signed = AEADCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      ).sign(payload);

      final invalidTag = Uint8List.fromList(signed.mac.bytes);
      invalidTag[0] ^= 0x01;

      final verifier = AEADStreamCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      );

      final isValid = await verifier.verifyStream(
        Stream<List<int>>.fromIterable([signed.data]),
        invalidTag,
      );

      expect(isValid, isFalse);
    });

    test('mac waits indefinitely for stream to be listened to', () async {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final payload = randomBytes(32);
      final macKey = randomBytes(32);

      final streamCipher = AEADStreamCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      );
      final result = streamCipher.signStream(
        Stream<List<int>>.fromIterable([payload]),
      );

      expect(() {
        return Future.wait(
          [
            result.mac,
            Future.delayed(
              Duration(milliseconds: 300),
              () => throw TimeoutException('Timeout'),
            ),
          ],
          eagerError: true,
        );
      }, throwsA(isA<TimeoutException>()));

      await result.drain();
      expect(await result.mac, isA<HashDigest>());
    });

    test('signStream propagates source stream errors to data and mac',
        () async {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final macKey = randomBytes(32);
      final streamCipher = AEADStreamCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      );

      final result = streamCipher.signStream(
        Stream<List<int>>.error(StateError('stream failure')),
      );
      final macErrorFuture = result.mac
          .then<Object?>((_) => null, onError: (Object error) => error);

      Object? streamError;
      final done = Completer<void>();
      result.listen(
        (_) {},
        onError: (Object error, StackTrace stackTrace) {
          streamError = error;
          if (!done.isCompleted) done.complete();
        },
        onDone: () {
          if (!done.isCompleted) done.complete();
        },
      );

      await done.future;
      expect(streamError, isA<StateError>());
      expect(await macErrorFuture, isA<StateError>());
    });

    test('cast is unsupported for AEADStreamCipher', () {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final macKey = randomBytes(32);
      final streamCipher = AEADStreamCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      );

      expect(
        () => streamCipher.cast<List<int>, List<int>>(),
        throwsUnsupportedError,
      );
    });

    test('poly1305 signStream keeps nonce in stream result wrappers', () async {
      final message = randomBytes(20);

      final chachaAlgo = ChaCha20(randomBytes(32)).poly1305();
      final chacha = chachaAlgo.signStream(
        Stream<List<int>>.fromIterable([message]),
      );
      expect(chacha, isA<AEADStreamResultWithIV>());
      expect((chacha as AEADStreamResultWithIV).iv, equals(chachaAlgo.iv));
      await chacha.drain();
      await expectLater(chacha.mac, completes);

      final salsaAlgo = Salsa20(randomBytes(32)).poly1305();
      final salsa = salsaAlgo.signStream(
        Stream<List<int>>.fromIterable([message]),
      );
      expect(salsa, isA<AEADStreamResultWithIV>());
      expect((salsa as AEADStreamResultWithIV).iv, equals(salsaAlgo.iv));
      await salsa.drain();
      await expectLater(salsa.mac, completes);

      final xchachaAlgo = XChaCha20(randomBytes(32)).poly1305();
      final xchacha = xchachaAlgo.signStream(
        Stream<List<int>>.fromIterable([message]),
      );
      expect(xchacha, isA<AEADStreamResultWithIV>());
      expect((xchacha as AEADStreamResultWithIV).iv, equals(xchachaAlgo.iv));
      await xchacha.drain();
      await expectLater(xchacha.mac, completes);

      final xsalsaAlgo = XSalsa20(randomBytes(32)).poly1305();
      final xsalsa = xsalsaAlgo.signStream(
        Stream<List<int>>.fromIterable([message]),
      );
      expect(xsalsa, isA<AEADStreamResultWithIV>());
      expect((xsalsa as AEADStreamResultWithIV).iv, equals(xsalsaAlgo.iv));
      await xsalsa.drain();
      await expectLater(xsalsa.mac, completes);
    });

    test('AEADStreamResult.withIV carries stream and tag verification',
        () async {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final payload = randomBytes(40);
      final macKey = randomBytes(32);

      final streamCipher = AEADStreamCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      );
      final result = streamCipher.signStream(
        Stream<List<int>>.fromIterable([payload]),
      );
      final wrappedIv = Uint8List.fromList(List<int>.filled(12, 9));
      final withIv = result.withIV(wrappedIv);

      final output = await withIv.expand((chunk) => chunk).toList();
      expect(output, equals(ChaCha20(key, nonce).convert(payload)));
      expect(withIv.iv, equals(wrappedIv));

      final tag = await withIv.mac;
      expect(await withIv.verify(tag.bytes), isTrue);

      final badTag = Uint8List.fromList(tag.bytes);
      badTag[0] ^= 0x80;
      expect(await withIv.verify(badTag), isFalse);
    });

    test('signStream forwards pause/resume/cancel to source subscription',
        () async {
      final key = randomBytes(32);
      final nonce = randomBytes(12);
      final macKey = randomBytes(32);
      final source = Stream<List<int>>.periodic(
        Duration(milliseconds: 5),
        (_) => randomBytes(4),
      ).take(100);

      final streamCipher = AEADStreamCipher(
        ChaCha20(key, nonce),
        Poly1305(Uint8List.fromList(macKey)),
      );
      final result = streamCipher.signStream(source);

      final sub = result.listen((_) {});

      await Future<void>.delayed(Duration(milliseconds: 20));
      sub.pause();
      await Future<void>.delayed(Duration(milliseconds: 20));
      sub.resume();
      await sub.cancel();
    });
  });
}
