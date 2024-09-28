// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib/random.dart';
import 'package:hashlib/codecs.dart';
import 'package:test/test.dart';

void main() {
  group("functionality tests", () {
    final key = Uint8List(32);
    final iv = Uint8List(16);
    final input = Uint8List(64);
    test("name is correct", () {
      expect(AES(key).gcm(iv).name, "AES/GCM/NoPadding");
    });
    test("accepts null IV", () {
      AESInGCMMode(key).encrypt(input);
    });
    test("encryptor name is correct", () {
      expect(AES(key).gcm(iv).encryptor.name, "AES#encrypt/GCM/NoPadding");
    });
    test("decryptor name is correct", () {
      expect(AES(key).gcm(iv).decryptor.name, "AES#decrypt/GCM/NoPadding");
    });
    test("tagSize must be between 1 and 16", () {
      for (int i = -10; i < 20; ++i) {
        if (i >= 1 && i <= 16) {
          AESInGCMModeEncryptSink(key, iv, null, i);
          AESInGCMModeDecryptSink(key, iv, null, i);
        } else {
          expect(
            () => AESInGCMModeEncryptSink(key, iv, null, i),
            throwsStateError,
          );
          expect(
            () => AESInGCMModeDecryptSink(key, iv, null, i),
            throwsStateError,
          );
        }
      }
    });
    test('encryptor sink test (no add after close)', () {
      final aes = AES(key).gcm(iv);
      var sink = aes.encryptor.createSink();
      int step = 8;
      var output = [];
      for (int i = 0; i < input.length; i += step) {
        output.addAll(sink.add(input.skip(i).take(step).toList()));
      }
      output.addAll(sink.close());
      expect(sink.closed, true);
      expect(output, equals(aes.encrypt(input)));
      expect(() => sink.add(Uint8List(16)), throwsStateError);
      sink.reset();
      expect([...sink.add(input), ...sink.close()], equals(output));
    });
    test('decryptor sink test (no add after close)', () {
      final aes = AES(key).gcm(iv);
      var ciphertext = aes.encrypt(input);
      var sink = aes.decryptor.createSink();
      int step = 8;
      var output = [];
      for (int i = 0; i < ciphertext.length; i += step) {
        output.addAll(sink.add(ciphertext.skip(i).take(step).toList()));
      }
      output.addAll(sink.close());
      expect(sink.closed, true);
      expect(output, equals(input));
      expect(() => sink.add(Uint8List(16)), throwsStateError);
      sink.reset();
      expect([...sink.add(ciphertext), ...sink.close()], equals(output));
    });
  });

  // https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
  group("NIST examples", () {
    group('AES-128/GCM', () {
      group('Test case 1', () {
        var key = fromHex('00000000000000000000000000000000');
        var iv = fromHex('000000000000000000000000');
        var plain = <int>[];
        var cipher = fromHex(
          '58e2fccefa7e3061367f1d57a4e7455a',
        );
        var aes = AES(key).gcm(iv);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 2', () {
        var key = fromHex('00000000000000000000000000000000');
        var iv = fromHex('000000000000000000000000');
        var plain = fromHex(
          '00000000000000000000000000000000',
        );
        var cipher = fromHex(
          '0388dace60b6a392f328c2b971b2fe78'
          'ab6e47d42cec13bdf53a67b21257bddf',
        );
        var aes = AES(key).gcm(iv);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 3', () {
        var key = fromHex('feffe9928665731c6d6a8f9467308308');
        var iv = fromHex('cafebabefacedbaddecaf888');
        var plain = fromHex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b391aafd255',
        );
        var cipher = fromHex(
          '42831ec2217774244b7221b784d0d49c'
          'e3aa212f2c02a4e035c17e2329aca12e'
          '21d514b25466931c7d8f6a5aac84aa05'
          '1ba30b396a0aac973d58e091473f5985'
          '4d5c2af327cd64a62cf35abd2ba6fab4',
        );
        var aes = AES(key).gcm(iv);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 4', () {
        var key = fromHex('feffe9928665731c6d6a8f9467308308');
        var iv = fromHex('cafebabefacedbaddecaf888');
        var aad = fromHex(
          'feedfacedeadbeeffeedfacedeadbeef'
          'abaddad2',
        );
        var plain = fromHex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b39',
        );
        var cipher = fromHex(
          '42831ec2217774244b7221b784d0d49c'
          'e3aa212f2c02a4e035c17e2329aca12e'
          '21d514b25466931c7d8f6a5aac84aa05'
          '1ba30b396a0aac973d58e091'
          '5bc94fbc3221a5db94fae95ae7121a47',
        );
        var aes = AES(key).gcm(iv, aad: aad);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 5', () {
        var key = fromHex('feffe9928665731c6d6a8f9467308308');
        var iv = fromHex('cafebabefacedbad');
        var aad = fromHex(
          'feedfacedeadbeeffeedfacedeadbeef'
          'abaddad2',
        );
        var plain = fromHex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b39',
        );
        var cipher = fromHex(
          '61353b4c2806934a777ff51fa22a4755'
          '699b2a714fcdc6f83766e5f97b6c7423'
          '73806900e49f24b22b097544d4896b42'
          '4989b5e1ebac0f07c23f4598'
          '3612d2e79e3b0785561be14aaca2fccb',
        );
        var aes = AES(key).gcm(iv, aad: aad);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 6', () {
        var key = fromHex('feffe9928665731c6d6a8f9467308308');
        var iv = fromHex(
          '9313225df88406e555909c5aff5269aa'
          '6a7a9538534f7da1e4c303d2a318a728'
          'c3c0c95156809539fcf0e2429a6b5254'
          '16aedbf5a0de6a57a637b39b',
        );
        var aad = fromHex(
          'feedfacedeadbeeffeedfacedeadbeef'
          'abaddad2',
        );
        var plain = fromHex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b39',
        );
        var cipher = fromHex(
          '8ce24998625615b603a033aca13fb894'
          'be9112a5c3a211a8ba262a3cca7e2ca7'
          '01e4a9a4fba43c90ccdcb281d48c7c6f'
          'd62875d2aca417034c34aee5'
          '619cc5aefffe0bfa462af43c1699d050',
        );
        var aes = AES(key).gcm(iv, aad: aad);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
    });
    group('AES-192/GCM', () {
      group('Test case 7', () {
        var key = fromHex(
          '00000000000000000000000000000000'
          '0000000000000000',
        );
        var iv = fromHex(
          '000000000000000000000000',
        );
        var plain = <int>[];
        var cipher = fromHex(
          'cd33b28ac773f74ba00ed1f312572435',
        );
        var aes = AES(key).gcm(iv);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 8', () {
        var key = fromHex(
          '00000000000000000000000000000000'
          '0000000000000000',
        );
        var iv = fromHex(
          '000000000000000000000000',
        );
        var plain = fromHex(
          '00000000000000000000000000000000',
        );
        var cipher = fromHex(
          '98e7247c07f0fe411c267e4384b0f600'
          '2ff58d80033927ab8ef4d4587514f0fb',
        );
        var aes = AES(key).gcm(iv);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 9', () {
        var key = fromHex(
          'feffe9928665731c6d6a8f9467308308'
          'feffe9928665731c',
        );
        var iv = fromHex(
          'cafebabefacedbaddecaf888',
        );
        var plain = fromHex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b391aafd255',
        );
        var cipher = fromHex(
          '3980ca0b3c00e841eb06fac4872a2757'
          '859e1ceaa6efd984628593b40ca1e19c'
          '7d773d00c144c525ac619d18c84a3f47'
          '18e2448b2fe324d9ccda2710acade256'
          '9924a7c8587336bfb118024db8674a14',
        );
        var aes = AES(key).gcm(iv);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 10', () {
        var key = fromHex(
          'feffe9928665731c6d6a8f9467308308'
          'feffe9928665731c',
        );
        var iv = fromHex('cafebabefacedbaddecaf888');
        var aad = fromHex(
          'feedfacedeadbeeffeedfacedeadbeef'
          'abaddad2',
        );
        var plain = fromHex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b39',
        );
        var cipher = fromHex(
          '3980ca0b3c00e841eb06fac4872a2757'
          '859e1ceaa6efd984628593b40ca1e19c'
          '7d773d00c144c525ac619d18c84a3f47'
          '18e2448b2fe324d9ccda2710'
          '2519498e80f1478f37ba55bd6d27618c',
        );
        var aes = AES(key).gcm(iv, aad: aad);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 11', () {
        var key = fromHex(
          'feffe9928665731c6d6a8f9467308308'
          'feffe9928665731c',
        );
        var iv = fromHex('cafebabefacedbad');
        var aad = fromHex(
          'feedfacedeadbeeffeedfacedeadbeef'
          'abaddad2',
        );
        var plain = fromHex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b39',
        );
        var cipher = fromHex(
          '0f10f599ae14a154ed24b36e25324db8'
          'c566632ef2bbb34f8347280fc4507057'
          'fddc29df9a471f75c66541d4d4dad1c9'
          'e93a19a58e8b473fa0f062f7'
          '65dcc57fcf623a24094fcca40d3533f8',
        );
        var aes = AES(key).gcm(iv, aad: aad);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 12', () {
        var key = fromHex(
          'feffe9928665731c6d6a8f9467308308'
          'feffe9928665731c',
        );
        var iv = fromHex(
          '9313225df88406e555909c5aff5269aa'
          '6a7a9538534f7da1e4c303d2a318a728'
          'c3c0c95156809539fcf0e2429a6b5254'
          '16aedbf5a0de6a57a637b39b',
        );
        var aad = fromHex(
          'feedfacedeadbeeffeedfacedeadbeef'
          'abaddad2',
        );
        var plain = fromHex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b39',
        );
        var cipher = fromHex(
          'd27e88681ce3243c4830165a8fdcf9ff'
          '1de9a1d8e6b447ef6ef7b79828666e45'
          '81e79012af34ddd9e2f037589b292db3'
          'e67c036745fa22e7e9b7373b'
          'dcf566ff291c25bbb8568fc3d376a6d9',
        );
        var aes = AES(key).gcm(iv, aad: aad);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
    });
    group('AES-256/GCM', () {
      group('Test case 13', () {
        var key = fromHex(
          '00000000000000000000000000000000'
          '00000000000000000000000000000000',
        );
        var iv = fromHex(
          '000000000000000000000000',
        );
        var plain = <int>[];
        var cipher = fromHex(
          '530f8afbc74536b9a963b4f1c4cb738b',
        );
        var aes = AES(key).gcm(iv);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 14', () {
        var key = fromHex(
          '00000000000000000000000000000000'
          '00000000000000000000000000000000',
        );
        var iv = fromHex(
          '000000000000000000000000',
        );
        var plain = fromHex(
          '00000000000000000000000000000000',
        );
        var cipher = fromHex(
          'cea7403d4d606b6e074ec5d3baf39d18'
          'd0d1c8a799996bf0265b98b5d48ab919',
        );
        var aes = AES(key).gcm(iv);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 15', () {
        var key = fromHex(
          'feffe9928665731c6d6a8f9467308308'
          'feffe9928665731c6d6a8f9467308308',
        );
        var iv = fromHex(
          'cafebabefacedbaddecaf888',
        );
        var plain = fromHex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b391aafd255',
        );
        var cipher = fromHex(
          '522dc1f099567d07f47f37a32a84427d'
          '643a8cdcbfe5c0c97598a2bd2555d1aa'
          '8cb08e48590dbb3da7b08b1056828838'
          'c5f61e6393ba7a0abcc9f662898015ad'
          'b094dac5d93471bdec1a502270e3cc6c',
        );
        var aes = AES(key).gcm(iv);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 16', () {
        var key = fromHex(
          'feffe9928665731c6d6a8f9467308308'
          'feffe9928665731c6d6a8f9467308308',
        );
        var iv = fromHex('cafebabefacedbaddecaf888');
        var aad = fromHex(
          'feedfacedeadbeeffeedfacedeadbeef'
          'abaddad2',
        );
        var plain = fromHex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b39',
        );
        var cipher = fromHex(
          '522dc1f099567d07f47f37a32a84427d'
          '643a8cdcbfe5c0c97598a2bd2555d1aa'
          '8cb08e48590dbb3da7b08b1056828838'
          'c5f61e6393ba7a0abcc9f662'
          '76fc6ece0f4e1768cddf8853bb2d551b',
        );
        var aes = AES(key).gcm(iv, aad: aad);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 17', () {
        var key = fromHex(
          'feffe9928665731c6d6a8f9467308308'
          'feffe9928665731c6d6a8f9467308308',
        );
        var iv = fromHex('cafebabefacedbad');
        var aad = fromHex(
          'feedfacedeadbeeffeedfacedeadbeef'
          'abaddad2',
        );
        var plain = fromHex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b39',
        );
        var cipher = fromHex(
          'c3762df1ca787d32ae47c13bf19844cb'
          'af1ae14d0b976afac52ff7d79bba9de0'
          'feb582d33934a4f0954cc2363bc73f78'
          '62ac430e64abe499f47c9b1f'
          '3a337dbf46a792c45e454913fe2ea8f2',
        );
        var aes = AES(key).gcm(iv, aad: aad);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
      group('Test case 18', () {
        var key = fromHex(
          'feffe9928665731c6d6a8f9467308308'
          'feffe9928665731c6d6a8f9467308308',
        );
        var iv = fromHex(
          '9313225df88406e555909c5aff5269aa'
          '6a7a9538534f7da1e4c303d2a318a728'
          'c3c0c95156809539fcf0e2429a6b5254'
          '16aedbf5a0de6a57a637b39b',
        );
        var aad = fromHex(
          'feedfacedeadbeeffeedfacedeadbeef'
          'abaddad2',
        );
        var plain = fromHex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b39',
        );
        var cipher = fromHex(
          '5a8def2f0c9e53f1f75d7853659e2a20'
          'eeb2b22aafde6419a058ab4f6f746bf4'
          '0fc0c3b780f244452da3ebf1c5d82cde'
          'a2418997200ef82e44ae7e3f'
          'a44a8266ee1c8eb0c8b5d4cf5ae9f19a',
        );
        var aes = AES(key).gcm(iv, aad: aad);
        test('encrypt', () {
          var actual = aes.encrypt(plain);
          expect(toHex(actual), equals(toHex(cipher)));
        });
        test('decrypt', () {
          var reverse = aes.decrypt(cipher);
          expect(toHex(reverse), equals(toHex(plain)));
        });
      });
    });
  });

  group('different tag length', () {
    group('with invalid tag length', () {
      var key = fromHex('00000000000000000000000000000000');
      var iv = fromHex('000000000000000000000000');
      var plain = <int>[];
      test('less than 1', () {
        expect(() => AES(key).gcm(iv, tagSize: 0).encrypt(plain),
            throwsStateError);
        expect(() => AES(key).gcm(iv, tagSize: -10).encrypt(plain),
            throwsStateError);
      });
      test('greater than 16', () {
        expect(() => AES(key).gcm(iv, tagSize: 17).encrypt(plain),
            throwsStateError);
        expect(() => AES(key).gcm(iv, tagSize: 32).encrypt(plain),
            throwsStateError);
      });
    });
    group('with empty message', () {
      var key = fromHex('00000000000000000000000000000000');
      var iv = fromHex('000000000000000000000000');
      var plain = <int>[];
      var cipher = fromHex(
        '58e2fccefa7e30',
      );
      var aes = AES(key).gcm(iv, tagSize: 7);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('with block message', () {
      var key = fromHex('00000000000000000000000000000000');
      var iv = fromHex('000000000000000000000000');
      var plain = fromHex(
        '00000000000000000000000000000000',
      );
      var cipher = fromHex(
        '0388dace60b6a392f328c2b971b2fe78'
        'ab6e47d42cec13bdf53a67',
      );
      var aes = AES(key).gcm(iv, tagSize: 11);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('with long message and aad', () {
      var key = fromHex(
        'feffe9928665731c6d6a8f9467308308'
        'feffe9928665731c6d6a8f9467308308',
      );
      var iv = fromHex('cafebabefacedbad');
      var aad = fromHex(
        'feedfacedeadbeeffeedfacedeadbeef'
        'abaddad2',
      );
      var plain = fromHex(
        'd9313225f88406e5a55909c5aff5269a'
        '86a7a9531534f7da2e4c303d8a318a72'
        '1c3c0c95956809532fcf0e2449a6b525'
        'b16aedf5aa0de657ba637b39',
      );
      var cipher = fromHex(
        'c3762df1ca787d32ae47c13bf19844cb'
        'af1ae14d0b976afac52ff7d79bba9de0'
        'feb582d33934a4f0954cc2363bc73f78'
        '62ac430e64abe499f47c9b1f'
        '3a337dbf46',
      );
      var aes = AES(key).gcm(iv, aad: aad, tagSize: 5);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
  });

  test('throws error when decrypting from partial ciphertext', () {
    var key = fromHex(
      '00000000000000000000000000000000'
      '00000000000000000000000000000000',
    );
    var iv = fromHex(
      '000000000000000000000000',
    );
    var cipher = fromHex(
      'cea7403d4d606b6e074ec5d3baf39d18'
      'd0d1c8a799996bf0265b98b5d48ab919',
    );
    var aes = AES(key).gcm(iv);
    aes.decrypt(cipher.take(32).toList());
    expect(() => aes.decrypt(cipher.take(25).toList()), throwsStateError);
    expect(() => aes.decrypt(cipher.take(16).toList()), throwsStateError);
    expect(() => aes.decrypt(cipher.take(4).toList()), throwsStateError);
    expect(() => aes.decrypt([]), throwsStateError);
  });

  group("96-bit nonce", () {
    group('AES-128', () {
      var key = 'abcdefghijklmnop'.codeUnits;
      var iv = 'lka9JLKasljk'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
        '6fa5eab56a6b6cc8a188e740fbc0f5de053709e77'
        'a56762da78c1c5dc2aacd78a6b324ee25307457ee',
      );
      var aes = AES(key).gcm(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('AES-192', () {
      var key = 'abcdefghijklmnopqrstuvwx'.codeUnits;
      var iv = 'lka9JLKasljk'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
        'b3f547eb73570c251560f1764a5e542aa661af83e'
        'd1e1733f67cc382beb7b73f76867d8c9236ad505d',
      );
      var aes = AES(key).gcm(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('AES-256', () {
      var key = 'abcdefghijklmnopqrstuvwxyz012345'.codeUnits;
      var iv = 'lka9JLKasljk'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
        '1a385320f4ae059f0ee2b784c8d715bd244e1415c'
        'f406bbcd44b2e8a59f23ba343e4957a10e73acb30',
      );
      var aes = AES(key).gcm(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
  });

  group("160-bit nonce", () {
    group('AES-128', () {
      var key = 'abcdefghijklmnop'.codeUnits;
      var iv = 'lka9JLKasljk1234kppe'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
        '42806b22cb59c04217e54c86b6d0f645b79488078'
        'eefe24686277af9486e7599f0a1f9f5c11d1f55c4',
      );
      var aes = AES(key).gcm(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('AES-192', () {
      var key = 'abcdefghijklmnopqrstuvwx'.codeUnits;
      var iv = 'lka9JLKasljk1234kppe'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
        'a6082bc1a74b363dbd6028b87819f77f4c7384e32'
        'ed02803c27b37b2717d16bbe939af9f1777c6a1d9',
      );
      var aes = AES(key).gcm(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('AES-256', () {
      var key = 'abcdefghijklmnopqrstuvwxyz012345'.codeUnits;
      var iv = 'lka9JLKasljk1234kppe'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
        '9ae339bfd7fa400ffd29d896c952baf20eaa1ee69'
        '462ee77e58435436dd5235440dc1947d26e37f956',
      );
      var aes = AES(key).gcm(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
  });

  group("64-bit nonce", () {
    group('AES-128', () {
      var key = 'abcdefghijklmnop'.codeUnits;
      var iv = 'lka9JLKa'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
        '7be8fb33e5d2e48b3b64890a68b9ba1b2b51157c3'
        '891b6d0b65c7ff455b046495be3e87fee9ed76f04',
      );
      var aes = AES(key).gcm(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('AES-192', () {
      var key = 'abcdefghijklmnopqrstuvwx'.codeUnits;
      var iv = 'lka9JLKa'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
        'bcc265c938514d712c35707a6c499f2340ba9219e'
        '9136ef7c0d2657e292ea3c17fa1aa6b46711dd9ca',
      );
      var aes = AES(key).gcm(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('AES-256', () {
      var key = 'abcdefghijklmnopqrstuvwxyz012345'.codeUnits;
      var iv = 'lka9JLKa'.codeUnits;
      var plain = 'A not very secret message'.codeUnits;
      var cipher = fromHex(
        '900377cd2b6e0c99d6dfaf36bc6a9710e2bd3d200'
        '79d3f2f04b9d51be50ef51416fd69f9aeea1d2971',
      );
      var aes = AES(key).gcm(iv);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
  });

  group('encryption <-> decryption', () {
    test("128-bit", () {
      var key = randomBytes(16);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).gcm(iv).encrypt(inp);
        var plain = AES(key).gcm(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("192-bit", () {
      var key = randomBytes(24);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).gcm(iv).encrypt(inp);
        var plain = AES(key).gcm(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("256-bit", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).gcm(iv).encrypt(inp);
        var plain = AES(key).gcm(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("with nonce and counter", () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var inp = randomBytes(j);
        var nonce = Nonce64.random();
        var aes = AESInCTRMode.nonce(key, nonce: nonce);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
  });

  group('sink test', () {
    test('encryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = randomBytes(16);
        final aes = AES(key).gcm(iv);

        var input = randomBytes(j);
        var cipher = aes.encrypt(input);

        var enc = aes.encryptor.createSink();
        var output = <int>[];
        for (int i = 0; i < input.length; i += 13) {
          output.addAll(enc.add(input.skip(i).take(13).toList()));
        }
        output.addAll(enc.close());
        expect(toHex(output), equals(toHex(cipher)), reason: '[size: $j]');

        var plain = aes.decrypt(output);
        expect(toHex(plain), equals(toHex(input)), reason: '[size: $j]');
      }
    });
    test('decryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = randomBytes(16);
        final aes = AES(key).gcm(iv);

        var input = randomBytes(j);
        var cipher = aes.encrypt(input);

        var dec = aes.decryptor.createSink();
        var output = <int>[];
        for (int i = 0; i < cipher.length; i += 23) {
          output.addAll(dec.add(cipher.skip(i).take(23).toList()));
        }
        output.addAll(dec.close());
        expect(toHex(output), equals(toHex(input)), reason: '[size: $j]');
      }
    });
    test('encryption + decryption', () {
      var key = randomBytes(32);
      for (int j = 0; j < 100; j++) {
        var iv = randomBytes(16);
        var input = randomBytes(j);

        final aes = AES(key).gcm(iv);
        var enc = aes.encryptor.createSink();
        var dec = aes.decryptor.createSink();

        var output = <int>[];
        for (int i = 0; i < input.length; i += 23) {
          var part = input.skip(i).take(23).toList();
          output.addAll(dec.add(enc.add(part)));
        }
        output.addAll(dec.add(enc.close()));
        output.addAll(dec.close());
        expect(toHex(output), equals(toHex(input)), reason: '[size: $j]');
      }
    });
  });

  test('reset iv', () {
    var iv = randomBytes(16);
    var key = randomBytes(24);
    var aes = AES(key).gcm(iv);
    for (int j = 0; j < 100; j++) {
      aes.resetIV();
      var inp = randomBytes(j);
      var cipher = aes.encrypt(inp);
      var plain = aes.decrypt(cipher);
      expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
    }
  });
}
