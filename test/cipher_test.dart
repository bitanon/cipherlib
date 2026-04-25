// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: always_declare_return_types

import 'dart:convert';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:test/test.dart';

// Concrete implementation of CipherBase for testing
class TestCipherBase extends CipherBase {
  @override
  String get name => 'TestCipherBase';
}

// Concrete implementation of Cipher for testing
class TestCipher extends Cipher {
  @override
  String get name => 'TestCipher';

  @override
  Uint8List convert(List<int> message) =>
      Uint8List.fromList(message.map((e) => e + 1).toList());
}

// Concrete implementation of StreamCipher for testing
class TestStreamCipher extends StreamCipher {
  @override
  String get name => 'TestStreamCipher';

  @override
  Uint8List convert(List<int> message) =>
      Uint8List.fromList(message.map((e) => e + 1).toList());

  @override
  Stream<Uint8List> bind(Stream<List<int>> stream) => stream.map(convert);
}

// Concrete implementation of SaltedCipher for testing
class TestSaltedCipher extends Cipher with SaltedCipher {
  @override
  String get name => 'TestSaltedCipher';

  @override
  final Uint8List iv;

  const TestSaltedCipher(this.iv);

  @override
  Uint8List convert(List<int> message) =>
      Uint8List.fromList(message.map((e) => e + 1).toList());
}

// Concrete implementation of SaltedCipher for testing
class TestCipherPair extends CipherPair {
  @override
  final encryptor = TestCipher();

  @override
  final decryptor = TestCipher();

  @override
  String get name => 'TestCipherPair';
}

void main() {
  group('validation', () {
    test('name should return the correct algorithm name', () {
      final cipher = TestCipherBase();
      expect(cipher.name, equals('TestCipherBase'));
    });

    // Test if the name property is implemented in derived classes
    test('derived class must implement name property', () {
      // Attempting to instantiate a class that doesn't implement `name`
      // should cause a compile-time error. Therefore, we simulate
      // the expectation that the property is correctly implemented.
      final cipher = TestCipherBase();
      expect(cipher.name.isNotEmpty, isTrue);
    });
  });

  test('convert transforms message correctly', () {
    final cipher = TestCipher();
    expect(cipher.name, 'TestCipher');
    final message = [1, 2, 3, 4, 5, 6];
    final result = cipher.convert(message);
    expect(result, Uint8List.fromList([2, 3, 4, 5, 6, 7]));
  });

  group('SaltedCipher Tests', () {
    test('resetIV replaces the IV with a new one', () {
      var iv = Uint8List(16);
      final cipher = TestSaltedCipher(iv);
      expect(cipher.name, 'TestSaltedCipher');
      expect(cipher.iv, iv);
      cipher.resetIV();
      expect(cipher.iv, iv);
      expect(cipher.iv, isNot(Uint8List(16)));
    });

    test('resetIV only mutates the IV view range', () {
      final backing = Uint8List.fromList(List.generate(32, (i) => i));
      final ivView = Uint8List.view(backing.buffer, 8, 16);
      final before = Uint8List.fromList(backing);
      final cipher = TestSaltedCipher(ivView);

      cipher.resetIV();

      for (int i = 0; i < 8; i++) {
        expect(
          backing[i],
          equals(before[i]),
          reason: 'prefix byte $i should remain unchanged',
        );
      }
      for (int i = 24; i < backing.length; i++) {
        expect(
          backing[i],
          equals(before[i]),
          reason: 'suffix byte $i should remain unchanged',
        );
      }
    });
  });

  group('StreamCipher Tests', () {
    test('bind transforms chunked input', () async {
      final cipher = TestStreamCipher();
      final stream = Stream<List<int>>.fromIterable([
        [1, 2],
        [3],
      ]);

      final chunks = await cipher.bind(stream).toList();
      expect(chunks, hasLength(2));
      expect(chunks[0], equals([2, 3]));
      expect(chunks[1], equals([4]));
    });

    test('stream flattens transformed chunks', () async {
      final cipher = TestStreamCipher();
      final stream = Stream<int>.fromIterable([1, 2, 3, 4]);

      final output = await cipher.stream(stream, 2).toList();
      expect(output, equals([2, 3, 4, 5]));
    });

    test('cast throws unsupported error', () {
      final cipher = TestStreamCipher();
      expect(
        () => cipher.cast<List<int>, Uint8List>(),
        throwsA(
          isA<UnsupportedError>().having(
            (e) => e.message,
            'message',
            'StreamCipher does not allow casting',
          ),
        ),
      );
    });
  });

  group('CipherPair Tests', () {
    final cipher = TestCipherPair();

    test('name is correct', () {
      expect(cipher.name, 'TestCipherPair');
    });

    test('encrypt method should encrypt data correctly', () {
      final message = [1, 2, 3];
      final encrypted = cipher.encrypt(message);
      expect(encrypted, [2, 3, 4]);
    });

    test('decrypt method should decrypt data correctly', () {
      final message = [2, 3, 4];
      final decrypted = cipher.decrypt(message);
      expect(decrypted, [3, 4, 5]);
    });

    test('encryptString method should encrypt string correctly', () {
      final message = 'abc';
      final encrypted = cipher.encryptString(message);
      expect(encrypted, [98, 99, 100]); // 'bcd'
    });

    test('decryptString method should decrypt string correctly', () {
      final message = 'abc';
      final decrypted = cipher.decryptString(message);
      expect(decrypted, [98, 99, 100]); // 'bcd'
    });

    test('encryptString method with encoding should encrypt string correctly',
        () {
      final message = 'abc';
      final encrypted = cipher.encryptString(message, utf8);
      expect(encrypted, [98, 99, 100]); // 'bcd'
    });

    test('decryptString method with encoding should decrypt string correctly',
        () {
      final message = 'abc';
      final decrypted = cipher.decryptString(message, utf8);
      expect(decrypted, [98, 99, 100]); // 'bcd'
    });
  });
}
