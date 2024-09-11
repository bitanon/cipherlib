// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/codecs.dart';
import 'package:test/test.dart';

void main() {
  group('Equality and hashCode tests', () {
    test('Nonce equality should work correctly', () {
      var bytes1 = fromHex('01020304');
      var bytes2 = fromHex('04030201');
      var nonce1 = Nonce.bytes(bytes1);
      var nonce2 = Nonce.bytes(bytes1);
      var nonce3 = Nonce.bytes(bytes2);
      expect(nonce1 == nonce2, isTrue);
      expect(nonce1 == nonce3, isFalse);
    });

    test('Nonce64 equality should work correctly', () {
      var bytes1 = fromHex('0102030405060708');
      var bytes2 = fromHex('0807060504030201');
      var nonce1 = Nonce64.bytes(bytes1);
      var nonce2 = Nonce64.bytes(bytes1);
      var nonce3 = Nonce64.bytes(bytes2);
      expect(nonce1 == nonce2, isTrue);
      expect(nonce1 == nonce3, isFalse);
    });

    test('hashCode should be consistent with equality', () {
      var bytes = fromHex('01020304');
      var nonce1 = Nonce.bytes(bytes);
      var nonce2 = Nonce.bytes(bytes);
      expect(nonce1.hashCode == nonce2.hashCode, isTrue);
    });
  });

  group('Nonce tests', () {
    test('Nonce.zero should create a nonce with all zeros', () {
      var nonce = Nonce.zero(4);
      expect(nonce.size, equals(4));
      expect(nonce.sizeInBits, equals(32));
      expect(nonce.bytes, equals(Uint8List.fromList([0, 0, 0, 0])));
    });

    test('Nonce.random should create a nonce with the specified size', () {
      var nonce = Nonce.random(16);
      expect(nonce.size, equals(16));
      expect(nonce.bytes.length, equals(16));
    });

    test('Nonce.bytes should copy the correct number of bytes', () {
      var data = [1, 2, 3, 4, 5];
      var nonce = Nonce.bytes(data, 3);
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3])));
      nonce = Nonce.bytes(data);
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3, 4, 5])));
    });

    test('Nonce.bytes should fill extrabytes with zeros', () {
      var data = [1, 2, 3];
      var nonce = Nonce.bytes(data, 5);
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3, 0, 0])));
    });

    test('Nonce.hex should convert hex string to bytes', () {
      var nonce = Nonce.hex('01020304');
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3, 4])));
    });

    test('Nonce.hex should create specific size nonce from hex string', () {
      var nonce = Nonce.hex('010203', 5);
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3, 0, 0])));
    });

    test('Nonce.reverse should reverse the bytes but keep the original', () {
      var original = [1, 2, 3, 4];
      var expected = [4, 3, 2, 1];
      var nonce = Nonce.bytes(original);
      var reversed = nonce.reverse();
      expect(nonce.bytes, equals(original));
      expect(reversed.bytes, equals(expected));
    });

    test('Nonce.padLeft should add padding to the left', () {
      var data = [1, 2, 3];
      var nonce = Nonce.bytes(data).padLeft(2);
      expect(nonce.bytes, equals(Uint8List.fromList([0, 0, 1, 2, 3])));
    });

    test('Nonce.padRight should add padding to the right', () {
      var data = [1, 2, 3];
      var nonce = Nonce.bytes(data).padRight(2);
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3, 0, 0])));
    });
  });

  group('Nonce64 tests', () {
    test('Nonce64.zero should create a 64-bit nonce with all zeros', () {
      var nonce = Nonce64.zero();
      expect(nonce.bytes, equals(Uint8List(8)));
    });

    test('Nonce64.random should create a 64-bit nonce', () {
      var nonce = Nonce64.random();
      expect(nonce.size, equals(8));
      expect(nonce.bytes.length, equals(8));
    });

    test('Nonce64.bytes should handle different byte lengths', () {
      var data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
      var nonce = Nonce64.bytes(data);
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8])));
    });

    test('Nonce64.bytes should fill remaining bytes with zeros', () {
      var data = [1, 2, 3, 4, 5];
      var nonce = Nonce64.bytes(data);
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3, 4, 5, 0, 0, 0])));
    });

    test('Nonce64.hex should create a 64-bit nonce from hex string', () {
      var nonce = Nonce64.hex('0102030405060708');
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8])));
    });

    test('Nonce64.hex should fill remaining bytes with zeros', () {
      var nonce = Nonce64.hex('0102030405');
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3, 4, 5, 0, 0, 0])));
    });

    test('Nonce64.int64 should create nonce from 64-bit integer', () {
      var nonce = Nonce64.int64(
        (0x01020304 << 32) ^ 0x05060708,
      );
      expect(nonce.bytes, equals(Uint8List.fromList([8, 7, 6, 5, 4, 3, 2, 1])));
    }, tags: ['vm-only']);

    test('Nonce64.int32 should create nonce from two 32-bit integers', () {
      var nonce = Nonce64.int32(0x01020304, 0x05060708);
      expect(nonce.bytes, equals(Uint8List.fromList([4, 3, 2, 1, 8, 7, 6, 5])));
    });

    test('Nonce64.int32 should create nonce from a 32-bit integer', () {
      var nonce = Nonce64.int32(0x01020304);
      expect(nonce.bytes, equals(Uint8List.fromList([4, 3, 2, 1, 0, 0, 0, 0])));
    });

    test('Nonce64.reverse should reverse the bytes but keep the original', () {
      var original = [1, 2, 3, 4, 5, 6, 7, 8];
      var expected = [8, 7, 6, 5, 4, 3, 2, 1];
      var nonce = Nonce64.bytes(original);
      var reversed = nonce.reverse();
      expect(nonce.bytes, equals(original));
      expect(reversed.bytes, equals(expected));
    });
  });

  group('Nonce128', () {
    test('should create a 128-bit nonce with zeros', () {
      final nonce = Nonce128.zero();
      expect(nonce.bytes, equals(Uint8List(16)));
    });

    test('should create a random 128-bit nonce', () {
      final nonce = Nonce128.random();
      expect(nonce.bytes.length, equals(16));
    });

    test('should create a 128-bit nonce from a list of bytes', () {
      final data = List<int>.generate(16, (i) => i);
      final nonce = Nonce128.bytes(data);
      expect(nonce.bytes, equals(Uint8List.fromList(data)));
    });

    test('Nonce128.bytes should fill remaining bytes with zeros', () {
      final nonce = Nonce128.bytes([1, 2, 3, 4, 5]);
      final expectedBytes = Uint8List.fromList([
        1, 2, 3, 4, 5, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      expect(nonce.bytes, equals(expectedBytes));
    });

    test('Nonce128.hex should create a 128-bit nonce from hex string', () {
      final data = '0102030405060708090A0B0C0D0E0F10';
      final expectedBytes = Uint8List.fromList([
        1, 2, 3, 4, 5, 6, 7, 8, //
        9, 10, 11, 12, 13, 14, 15, 16
      ]);
      final nonce = Nonce128.hex(data);
      expect(nonce.bytes, equals(expectedBytes));
    });

    test('Nonce128.hex should fill remaining bytes with zeros', () {
      final data = '0102030405';
      final expectedBytes = Uint8List.fromList([
        1, 2, 3, 4, 5, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      final nonce = Nonce128.hex(data);
      expect(nonce.bytes, equals(expectedBytes));
    });

    test('Nonce128.int64 should create a nonce from two 64-bit integers', () {
      final nonce = Nonce128.int64(
        (0x090A0B0C << 32) ^ 0x0D0E0F10,
        (0x01020304 << 32) ^ 0x05060708,
      );
      final expectedBytes = Uint8List.fromList([
        0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, //
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
      ]);
      expect(nonce.bytes, equals(expectedBytes));
    }, tags: ['vm-only']);

    test('Nonce128.int64 should create a nonce from one 64-bit integers', () {
      final nonce = Nonce128.int64(
        (0x090A0B0C << 32) ^ 0x0D0E0F10,
      );
      final expectedBytes = Uint8List.fromList([
        0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, //
        0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      expect(nonce.bytes, equals(expectedBytes));
    }, tags: ['vm-only']);

    test('Nonce128.int32 should create a nonce from four 32-bit integers', () {
      final nonce = Nonce128.int32(
        0x0D0E0F10,
        0x090A0B0C,
        0x05060708,
        0x01020304,
      );
      final expectedBytes = Uint8List.fromList([
        0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, //
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
      ]);
      expect(nonce.bytes, equals(expectedBytes));
    });

    test('Nonce128.int32 should create a nonce from three 32-bit integers', () {
      final nonce = Nonce128.int32(
        0x0D0E0F10,
        0x090A0B0C,
        0x05060708,
      );
      final expectedBytes = Uint8List.fromList([
        0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, //
        0x08, 0x07, 0x06, 0x05, 0, 0, 0, 0,
      ]);
      expect(nonce.bytes, equals(expectedBytes));
    });

    test('Nonce128.int32 should create a nonce from two 32-bit integers', () {
      final nonce = Nonce128.int32(
        0x0D0E0F10,
        0x090A0B0C,
      );
      final expectedBytes = Uint8List.fromList([
        0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, //
        0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      expect(nonce.bytes, equals(expectedBytes));
    });

    test('Nonce128.int32 should create a nonce from one 32-bit integers', () {
      final nonce = Nonce128.int32(
        0x0D0E0F10,
      );
      final expectedBytes = Uint8List.fromList([
        0x10, 0x0F, 0x0E, 0x0D, 0, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      expect(nonce.bytes, equals(expectedBytes));
    });

    test('Nonce128.reverse should reverse the bytes but keep the original', () {
      final originalBytes = [
        0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, //
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
      ];
      final nonce = Nonce128.bytes(originalBytes);
      final reversedNonce = nonce.reverse();
      final expectedBytes = Uint8List.fromList([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
      ]);
      expect(nonce.bytes, equals(originalBytes));
      expect(reversedNonce.bytes, equals(expectedBytes));
    });
  });
}
