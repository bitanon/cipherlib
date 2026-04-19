// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:test/test.dart';

void main() {
  group('Nonce', () {
    test('Nonce equality should work correctly', () {
      var bytes1 = fromHex('01020304');
      var bytes2 = fromHex('04030201');
      var nonce1 = Nonce.bytes(bytes1);
      var nonce2 = Nonce.bytes(bytes1);
      var nonce3 = Nonce.bytes(bytes2);
      var nonce4 = nonce1;
      expect(nonce1 == nonce2, isFalse);
      expect(nonce1 == nonce3, isFalse);
      expect(nonce1 == nonce4, isTrue);
    });

    test('Nonce.zero should create a nonce with all zeros', () {
      var nonce = Nonce.zero(4);
      expect(nonce.length, equals(4));
      expect(nonce.lengthInBits, equals(32));
      expect(nonce.bytes, equals(Uint8List.fromList([0, 0, 0, 0])));
    });

    test('Nonce.random should create a nonce with the specified size', () {
      var nonce = Nonce.random(16);
      expect(nonce.length, equals(16));
      expect(nonce.bytes.length, equals(16));
    });

    test('Nonce.bytes should copy the correct number of bytes', () {
      var data = [1, 2, 3, 4, 5];
      var nonce = Nonce.bytes(data, 3);
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3])));
      nonce = Nonce.bytes(data);
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3, 4, 5])));
    });

    test('Nonce named constructor forwards to Nonce.bytes', () {
      final data = [9, 8, 7, 6, 5];
      expect(
        Nonce(data, 3).bytes,
        equals(Nonce.bytes(data, 3).bytes),
      );
      expect(Nonce(data).bytes, equals(Nonce.bytes(data).bytes));
    });

    test('Nonce.bytes truncates when data is longer than size', () {
      final long = List<int>.generate(12, (i) => i + 1);
      final nonce = Nonce.bytes(long, 4);
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3, 4])));
    });

    test('Nonce.hex truncates decoded bytes when size is smaller', () {
      final nonce = Nonce.hex('010203040506', 3);
      expect(nonce.bytes, equals(Uint8List.fromList([1, 2, 3])));
    });

    test('Nonce.zero(0) yields empty bytes', () {
      final nonce = Nonce.zero(0);
      expect(nonce.length, equals(0));
      expect(nonce.lengthInBits, equals(0));
      expect(nonce.bytes, equals(Uint8List(0)));
    });

    test('Nonce.pad with zero padLength preserves bytes', () {
      final n = Nonce.bytes([1, 2, 3]);
      expect(n.padLeft(0).bytes, equals(n.bytes));
      expect(n.padRight(0).bytes, equals(n.bytes));
      expect(n.pad(0).bytes, equals(n.bytes));
    });

    test('Nonce.reverse is involutive up to new instances', () {
      final n = Nonce.bytes([1, 2, 3, 4]);
      expect(n.reverse().reverse().bytes, equals(n.bytes));
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

    test('Nonce.pad should add padding to the left and right', () {
      var data = [1, 2, 3];
      var nonce = Nonce.bytes(data).pad(2);
      expect(nonce.bytes, equals(([0, 0, 1, 2, 3, 0, 0])));
    });

    test('Nonce inherits ByteCollector toString as hex', () {
      expect(Nonce.bytes([0xab, 0xcd]).toString(), equals('abcd'));
    });
  });

  group('Nonce64', () {
    test('Nonce64 equality should work correctly', () {
      var bytes1 = fromHex('0102030405060708');
      var bytes2 = fromHex('0807060504030201');
      var nonce1 = Nonce64.bytes(bytes1);
      var nonce2 = Nonce64.bytes(bytes1);
      var nonce3 = Nonce64.bytes(bytes2);
      var nonce4 = nonce1;
      expect(nonce1 == nonce2, isFalse);
      expect(nonce1 == nonce3, isFalse);
      expect(nonce1 == nonce4, isTrue);
    });

    test('Nonce64.zero should create a 64-bit nonce with all zeros', () {
      var nonce = Nonce64.zero();
      expect(nonce.bytes, equals(Uint8List(8)));
    });

    test('Nonce64.random should create a 64-bit nonce', () {
      var nonce = Nonce64.random();
      expect(nonce.length, equals(8));
      expect(nonce.bytes.length, equals(8));
    });

    test('Nonce64.bytes should handle different byte lengths', () {
      var data = [1, 2, 3, 4, 5, 6, 7, 8, 9];
      var nonce = Nonce64.bytes(data);
      expect(nonce.bytes, equals(([1, 2, 3, 4, 5, 6, 7, 8])));
    });

    test('Nonce64 named constructor forwards to Nonce64.bytes', () {
      final data = [1, 2, 3, 4, 5, 6, 7, 8];
      expect(Nonce64(data).bytes, equals(Nonce64.bytes(data).bytes));
    });

    test('Nonce64 length and lengthInBits', () {
      final n = Nonce64.zero();
      expect(n.length, equals(8));
      expect(n.lengthInBits, equals(64));
    });

    test('Nonce64.reverse is involutive', () {
      final n = Nonce64.bytes([1, 2, 3, 4, 5, 6, 7, 8]);
      expect(n.reverse().reverse().bytes, equals(n.bytes));
    });

    test('Nonce64.bytes should fill remaining bytes with zeros', () {
      var data = [1, 2, 3, 4, 5];
      var nonce = Nonce64.bytes(data);
      expect(nonce.bytes, equals(([1, 2, 3, 4, 5, 0, 0, 0])));
    });

    test('Nonce64.hex creates a 64-bit nonce from hex string', () {
      var nonce = Nonce64.hex('0102030405060708');
      expect(nonce.bytes, equals(([1, 2, 3, 4, 5, 6, 7, 8])));
    });

    test('Nonce64.hex fills remaining bytes with zeros', () {
      var nonce = Nonce64.hex('0102030405');
      expect(nonce.bytes, equals(([1, 2, 3, 4, 5, 0, 0, 0])));
    });

    test('Nonce64.int64 creates nonce from 64-bit integer', () {
      var nonce = Nonce64.int64(
        (0x01020304 << 32) ^ 0x05060708,
      );
      expect(nonce.bytes, equals(([8, 7, 6, 5, 4, 3, 2, 1])));
    }, tags: ['vm-only']);

    test('Nonce64.int64(0) yields eight zero bytes', () {
      expect(Nonce64.int64(0).bytes, equals(Uint8List(8)));
    });

    test(
      'Nonce64.int64(-1) yields eight 0xff bytes (unsigned expansion)',
      () {
        expect(
          Nonce64.int64(-1).bytes,
          equals(Uint8List.fromList(List.filled(8, 0xff))),
        );
      },
      tags: ['vm-only'],
    );

    test('Nonce64.int32 creates nonce from two 32-bit integers', () {
      var nonce = Nonce64.int32(0x01020304, 0x05060708);
      expect(nonce.bytes, equals(Uint8List.fromList([4, 3, 2, 1, 8, 7, 6, 5])));
    });

    test('Nonce64.int32 creates nonce from a 32-bit integer', () {
      var nonce = Nonce64.int32(0x01020304);
      expect(nonce.bytes, equals(Uint8List.fromList([4, 3, 2, 1, 0, 0, 0, 0])));
    });

    test('Nonce64.reverse reverses the bytes but keep the original', () {
      var original = [1, 2, 3, 4, 5, 6, 7, 8];
      var expected = [8, 7, 6, 5, 4, 3, 2, 1];
      var nonce = Nonce64.bytes(original);
      var reversed = nonce.reverse();
      expect(nonce.bytes, equals(original));
      expect(reversed.bytes, equals(expected));
    });
  });

  group('Nonce128', () {
    test('Nonce128 equality should work correctly', () {
      var bytes1 = fromHex('01020304050607081011121314151617');
      var bytes2 = fromHex('17161514131211100807060504030201');
      var nonce1 = Nonce128.bytes(bytes1);
      var nonce2 = Nonce128.bytes(bytes1);
      var nonce3 = Nonce128.bytes(bytes2);
      var nonce4 = nonce1;
      expect(nonce1 == nonce2, isFalse);
      expect(nonce1 == nonce3, isFalse);
      expect(nonce1 == nonce4, isTrue);
    });

    test('creates a 128-bit nonce with zeros', () {
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

    test('Nonce128 named constructor forwards to Nonce128.bytes', () {
      final data = List<int>.generate(16, (i) => i + 1);
      expect(Nonce128(data).bytes, equals(Nonce128.bytes(data).bytes));
    });

    test('Nonce128.bytes truncates when more than 16 bytes provided', () {
      final long = List<int>.generate(20, (i) => i + 1);
      final nonce = Nonce128.bytes(long);
      expect(nonce.bytes, equals(Uint8List.fromList(long.sublist(0, 16))));
    });

    test('Nonce128 length and lengthInBits', () {
      final n = Nonce128.zero();
      expect(n.length, equals(16));
      expect(n.lengthInBits, equals(128));
    });

    test('Nonce128.reverse is involutive', () {
      final n = Nonce128.bytes(List<int>.generate(16, (i) => i));
      expect(n.reverse().reverse().bytes, equals(n.bytes));
    });

    test('Nonce128.bytes fills remaining bytes with zeros', () {
      final nonce = Nonce128.bytes([1, 2, 3, 4, 5]);
      final expectedBytes = Uint8List.fromList([
        1, 2, 3, 4, 5, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      expect(nonce.bytes, equals(expectedBytes));
    });

    test('Nonce128.hex creates a 128-bit nonce from hex string', () {
      final data = '0102030405060708090A0B0C0D0E0F10';
      final expectedBytes = Uint8List.fromList([
        1, 2, 3, 4, 5, 6, 7, 8, //
        9, 10, 11, 12, 13, 14, 15, 16
      ]);
      final nonce = Nonce128.hex(data);
      expect(nonce.bytes, equals(expectedBytes));
    });

    test('Nonce128.hex fills remaining bytes with zeros', () {
      final data = '0102030405';
      final expectedBytes = Uint8List.fromList([
        1, 2, 3, 4, 5, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      final nonce = Nonce128.hex(data);
      expect(nonce.bytes, equals(expectedBytes));
    });

    test('Nonce128.int64 creates a nonce from two 64-bit integers', () {
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

    test('Nonce128.int64 creates a nonce from one 64-bit integers', () {
      final nonce = Nonce128.int64(
        (0x090A0B0C << 32) ^ 0x0D0E0F10,
      );
      final expectedBytes = Uint8List.fromList([
        0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, //
        0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      expect(nonce.bytes, equals(expectedBytes));
    }, tags: ['vm-only']);

    test('Nonce128.int64(0, 0) yields sixteen zero bytes', () {
      expect(Nonce128.int64(0, 0).bytes, equals(Uint8List(16)));
    });

    test('Nonce128.int32 creates a nonce from four 32-bit integers', () {
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

    test('Nonce128.int32 creates a nonce from three 32-bit integers', () {
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

    test('Nonce128.int32 creates a nonce from two 32-bit integers', () {
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

    test('Nonce128.int32 creates a nonce from one 32-bit integers', () {
      final nonce = Nonce128.int32(
        0x0D0E0F10,
      );
      final expectedBytes = Uint8List.fromList([
        0x10, 0x0F, 0x0E, 0x0D, 0, 0, 0, 0, //
        0, 0, 0, 0, 0, 0, 0, 0,
      ]);
      expect(nonce.bytes, equals(expectedBytes));
    });

    test('Nonce128.reverse reverses the bytes but keep the original', () {
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
