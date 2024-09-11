// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

// ignore_for_file: always_declare_return_types

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:cipherlib/cipherlib.dart';

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
  CipherSink createSink() => MockCipherSink();
}

// Concrete implementation of SaltedCipher for testing
class TestSaltedCipher extends Cipher with SaltedCipher {
  @override
  String get name => 'TestSaltedCipher';

  @override
  final Uint8List iv;

  const TestSaltedCipher(this.iv);

  @override
  CipherSink createSink() => MockCipherSink();
}

// Concrete implementation of SaltedCipher for testing
class TestCollateCipher extends CollateCipher {
  @override
  final encryptor = TestCipher();

  @override
  final decryptor = TestCipher();

  @override
  String get name => 'TestCollateCipher';
}

// Mock implementation of CipherSink for testing
class MockCipherSink implements CipherSink {
  bool _closed = false;

  @override
  add(List<int> data, [bool last = false, int start = 0, int? end]) {
    _closed = last;
    return Uint8List.fromList(
      data.sublist(start, end).map((e) => e + 1).toList(),
    );
  }

  @override
  get closed => _closed;

  @override
  close() {
    _closed = true;
    return Uint8List(0);
  }

  @override
  reset() {
    _closed = false;
  }
}

void main() {
  group('CipherBase Tests', () {
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

  group('StreamCipherBase Tests', () {
    // Test the bind method for StreamCipherBase
    test('bind transforms stream correctly', () async {
      final cipher = TestCipher();
      final input = [
        [1, 2, 3],
        [4, 5, 6],
      ];
      final expected = input.map((e) => e.map((e) => e + 1).toList()).toList();
      final inputStream = Stream.fromIterable(input);
      final resultStream = cipher.bind(inputStream);
      final result = await resultStream.toList();
      expect(result, equals(expected));
    });

    // Test the stream method for StreamCipherBase
    test('stream transforms stream of integers correctly', () async {
      final cipher = TestCipher();
      final inputStream = Stream.fromIterable([1, 2, 3, 4, 5, 6]);
      final resultStream = cipher.stream(inputStream);
      final result = await resultStream.toList();
      expect(result, Uint8List.fromList([2, 3, 4, 5, 6, 7]));
    });

    test('cast method should cast StreamTransformer correctly', () {
      final cipher = TestCipher();
      expect(() => cipher.cast<String, String>(), throwsUnsupportedError);
    });
  });

  group('Cipher Tests', () {
    test('convert transforms message correctly', () {
      final cipher = TestCipher();
      expect(cipher.name, 'TestCipher');
      final message = [1, 2, 3, 4, 5, 6];
      final result = cipher.convert(message);
      expect(result, Uint8List.fromList([2, 3, 4, 5, 6, 7]));
    });

    test('bind with empty stream returns empty Uint8List', () async {
      final cipher = TestCipher();
      final inputStream = Stream<List<int>>.empty();
      final resultStream = cipher.bind(inputStream);
      final result = await resultStream.toList();
      expect(result, [Uint8List(0)]);
    });

    test('stream with empty stream returns empty list', () async {
      final cipher = TestCipher();
      final inputStream = Stream<int>.empty();
      final resultStream = cipher.stream(inputStream);
      final result = await resultStream.toList();
      expect(result, []);
    });

    test('stream transforms stream of integers correctly', () async {
      final cipher = TestCipher();
      final input = List.generate(2500, (index) => index % 256);
      final outout = List.generate(2500, (index) => (index + 1) % 256);
      final inputStream = Stream.fromIterable(input);
      final resultStream = cipher.stream(inputStream);
      final result = await resultStream.toList();
      expect(result, equals(outout));
    });
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
  });

  group('CollateCipher Tests', () {
    final cipher = TestCollateCipher();

    test('name is correct', () {
      expect(cipher.name, 'TestCollateCipher');
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

    test('encryptStream method should encrypt stream correctly', () async {
      final stream = Stream.fromIterable([1, 2, 3]);
      final encryptedStream = cipher.encryptStream(stream);
      final encrypted = await encryptedStream.toList();
      expect(encrypted, [2, 3, 4]);
    });

    test('decryptStream method should decrypt stream correctly', () async {
      final stream = Stream.fromIterable([2, 3, 4]);
      final decryptedStream = cipher.decryptStream(stream);
      final decrypted = await decryptedStream.toList();
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
