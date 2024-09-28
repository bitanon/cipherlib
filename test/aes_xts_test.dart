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
      expect(AES(key).xts(iv).name, "AES/XTS/NoPadding");
    });
    test("accepts null IV", () {
      AESInXTSMode(key).encrypt(input);
    });
    test("encryptor name is correct", () {
      expect(AES(key).xts(iv).encryptor.name, "AES#encrypt/XTS/NoPadding");
    });
    test("decryptor name is correct", () {
      expect(AES(key).xts(iv).decryptor.name, "AES#decrypt/XTS/NoPadding");
    });
    test("iv must be 16 bytes", () {
      for (int i = 0; i < 20; ++i) {
        if (i == 16) {
          AESInXTSMode(key, Uint8List(i));
        } else {
          expect(() => AESInXTSMode(key, Uint8List(i)), throwsStateError);
        }
      }
    });
    test('encryptor sink test (no add after close)', () {
      final aes = AES(key).xts(iv);
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
      final aes = AES(key).xts(iv);
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
    test('reset iv', () {
      var key = randomBytes(32);
      var iv = randomBytes(16);
      var aes = AES(key).xts(iv);
      for (int j = 16; j < 100; j++) {
        aes.resetIV();
        var inp = randomBytes(j);
        var cipher = aes.encrypt(inp);
        var plain = aes.decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test('does not allow message size < 16 bytes', () {
      var key = randomBytes(32);
      var iv = randomBytes(16);
      var aes = AES(key).xts(iv);
      for (int j = 0; j < 16; j++) {
        var inp = Uint8List(j);
        expect(() => aes.encrypt(inp), throwsStateError, reason: '[size: $j]');
        expect(() => aes.decrypt(inp), throwsStateError, reason: '[size: $j]');
      }
    });
    test('does not allow invalid key sizes', () {
      for (int x in [16, 24, 33, 49, 65]) {
        var key = Uint8List(x);
        var iv = Uint8List(16);
        expect(() => AES(key).xts(iv), throwsStateError, reason: '[size: $x]');
      }
    });
  });

  // https://csrc.nist.gov/pubs/sp/800/38/a/finals
  group('IEEE Standard 1619-2007', () {
    group('Vector 1', () {
      var key = fromHex(
        '00000000000000000000000000000000'
        '00000000000000000000000000000000',
      );
      var sector = Nonce64.zero();
      var plain = fromHex(
        '00000000000000000000000000000000'
        '00000000000000000000000000000000',
      );
      var cipher = fromHex(
        '917cf69ebd68b2ec9b9fe9a3eadda692'
        'cd43d2f59598ed858c02c2652fbf922e',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 2', () {
      var key = fromHex(
        '11111111111111111111111111111111'
        '22222222222222222222222222222222',
      );
      var sector = Nonce64.hex('3333333333');
      var plain = fromHex(
        '44444444444444444444444444444444'
        '44444444444444444444444444444444',
      );
      var cipher = fromHex(
        'c454185e6a16936e39334038acef838b'
        'fb186fff7480adc4289382ecd6d394f0',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 3', () {
      var key = fromHex(
        'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'
        '22222222222222222222222222222222',
      );
      var sector = Nonce64.hex('3333333333');
      var plain = fromHex(
        '44444444444444444444444444444444'
        '44444444444444444444444444444444',
      );
      var cipher = fromHex(
        'af85336b597afc1a900b2eb21ec949d2'
        '92df4c047e0b21532186a5971a227a89',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 4', () {
      var key = fromHex(
        '27182818284590452353602874713526'
        '31415926535897932384626433832795',
      );
      var sector = Nonce64.zero();
      var plain = fromHex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      );
      var cipher = fromHex(
        '27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c'
        'c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412'
        '328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce'
        '93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad0265'
        '5ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8'
        'a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f434'
        '1332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c'
        '5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e'
        '94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc'
        '1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3'
        'e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344'
        'b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd'
        '74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752'
        'afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203e'
        'bb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18d'
        'eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 5', () {
      var key = fromHex(
        '27182818284590452353602874713526'
        '31415926535897932384626433832795',
      );
      var sector = Nonce64.int32(0x01);
      var plain = fromHex(
        '27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c'
        'c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412'
        '328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce'
        '93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad0265'
        '5ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8'
        'a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f434'
        '1332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c'
        '5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e'
        '94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc'
        '1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3'
        'e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344'
        'b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd'
        '74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752'
        'afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203e'
        'bb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18d'
        'eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568',
      );
      var cipher = fromHex(
        '264d3ca8512194fec312c8c9891f279fefdd608d0c027b60483a3fa811d65ee5'
        '9d52d9e40ec5672d81532b38b6b089ce951f0f9c35590b8b978d175213f329bb'
        '1c2fd30f2f7f30492a61a532a79f51d36f5e31a7c9a12c286082ff7d2394d18f'
        '783e1a8e72c722caaaa52d8f065657d2631fd25bfd8e5baad6e527d763517501'
        'c68c5edc3cdd55435c532d7125c8614deed9adaa3acade5888b87bef641c4c99'
        '4c8091b5bcd387f3963fb5bc37aa922fbfe3df4e5b915e6eb514717bdd2a7407'
        '9a5073f5c4bfd46adf7d282e7a393a52579d11a028da4d9cd9c77124f9648ee3'
        '83b1ac763930e7162a8d37f350b2f74b8472cf09902063c6b32e8c2d9290cefb'
        'd7346d1c779a0df50edcde4531da07b099c638e83a755944df2aef1aa31752fd'
        '323dcb710fb4bfbb9d22b925bc3577e1b8949e729a90bbafeacf7f7879e7b114'
        '7e28ba0bae940db795a61b15ecf4df8db07b824bb062802cc98a9545bb2aaeed'
        '77cb3fc6db15dcd7d80d7d5bc406c4970a3478ada8899b329198eb61c193fb62'
        '75aa8ca340344a75a862aebe92eee1ce032fd950b47d7704a3876923b4ad6284'
        '4bf4a09c4dbe8b4397184b7471360c9564880aedddb9baa4af2e75394b08cd32'
        'ff479c57a07d3eab5d54de5f9738b8d27f27a9f0ab11799d7b7ffefb2704c95c'
        '6ad12c39f1e867a4b7b1d7818a4b753dfd2a89ccb45e001a03a867b187f225dd',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 6', () {
      var key = fromHex(
        '27182818284590452353602874713526'
        '31415926535897932384626433832795',
      );
      var sector = Nonce64.int32(0x02);
      var plain = fromHex(
        '264d3ca8512194fec312c8c9891f279fefdd608d0c027b60483a3fa811d65ee5'
        '9d52d9e40ec5672d81532b38b6b089ce951f0f9c35590b8b978d175213f329bb'
        '1c2fd30f2f7f30492a61a532a79f51d36f5e31a7c9a12c286082ff7d2394d18f'
        '783e1a8e72c722caaaa52d8f065657d2631fd25bfd8e5baad6e527d763517501'
        'c68c5edc3cdd55435c532d7125c8614deed9adaa3acade5888b87bef641c4c99'
        '4c8091b5bcd387f3963fb5bc37aa922fbfe3df4e5b915e6eb514717bdd2a7407'
        '9a5073f5c4bfd46adf7d282e7a393a52579d11a028da4d9cd9c77124f9648ee3'
        '83b1ac763930e7162a8d37f350b2f74b8472cf09902063c6b32e8c2d9290cefb'
        'd7346d1c779a0df50edcde4531da07b099c638e83a755944df2aef1aa31752fd'
        '323dcb710fb4bfbb9d22b925bc3577e1b8949e729a90bbafeacf7f7879e7b114'
        '7e28ba0bae940db795a61b15ecf4df8db07b824bb062802cc98a9545bb2aaeed'
        '77cb3fc6db15dcd7d80d7d5bc406c4970a3478ada8899b329198eb61c193fb62'
        '75aa8ca340344a75a862aebe92eee1ce032fd950b47d7704a3876923b4ad6284'
        '4bf4a09c4dbe8b4397184b7471360c9564880aedddb9baa4af2e75394b08cd32'
        'ff479c57a07d3eab5d54de5f9738b8d27f27a9f0ab11799d7b7ffefb2704c95c'
        '6ad12c39f1e867a4b7b1d7818a4b753dfd2a89ccb45e001a03a867b187f225dd',
      );
      var cipher = fromHex(
        'fa762a3680b76007928ed4a4f49a9456031b704782e65e16cecb54ed7d017b5e'
        '18abd67b338e81078f21edb7868d901ebe9c731a7c18b5e6dec1d6a72e078ac9'
        'a4262f860beefa14f4e821018272e411a951502b6e79066e84252c3346f3aa62'
        '344351a291d4bedc7a07618bdea2af63145cc7a4b8d4070691ae890cd65733e7'
        '946e9021a1dffc4c59f159425ee6d50ca9b135fa6162cea18a939838dc000fb3'
        '86fad086acce5ac07cb2ece7fd580b00cfa5e98589631dc25e8e2a3daf2ffdec'
        '26531659912c9d8f7a15e5865ea8fb5816d6207052bd7128cd743c12c8118791'
        'a4736811935eb982a532349e31dd401e0b660a568cb1a4711f552f55ded59f1f'
        '15bf7196b3ca12a91e488ef59d64f3a02bf45239499ac6176ae321c4a211ec54'
        '5365971c5d3f4f09d4eb139bfdf2073d33180b21002b65cc9865e76cb24cd92c'
        '874c24c18350399a936ab3637079295d76c417776b94efce3a0ef7206b151105'
        '19655c956cbd8b2489405ee2b09a6b6eebe0c53790a12a8998378b33a5b71159'
        '625f4ba49d2a2fdba59fbf0897bc7aabd8d707dc140a80f0f309f835d3da54ab'
        '584e501dfa0ee977fec543f74186a802b9a37adb3e8291eca04d66520d229e60'
        '401e7282bef486ae059aa70696e0e305d777140a7a883ecdcb69b9ff938e8a42'
        '31864c69ca2c2043bed007ff3e605e014bcf518138dc3a25c5e236171a2d01d6',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 7', () {
      var key = fromHex(
        '27182818284590452353602874713526'
        '31415926535897932384626433832795',
      );
      var sector = Nonce64.int32(0xfd);
      var plain = fromHex(
        '8e41b78c390b5af9d758bb214a67e9f6bf7727b09ac6124084c37611398fa45d'
        'aad94868600ed391fb1acd4857a95b466e62ef9f4b377244d1c152e7b30d731a'
        'ad30c716d214b707aed99eb5b5e580b3e887cf7497465651d4b60e6042051da3'
        '693c3b78c14489543be8b6ad0ba629565bba202313ba7b0d0c94a3252b676f46'
        'cc02ce0f8a7d34c0ed229129673c1f61aed579d08a9203a25aac3a77e9db6026'
        '7996db38df637356d9dcd1632e369939f2a29d89345c66e05066f1a3677aef18'
        'dea4113faeb629e46721a66d0a7e785d3e29af2594eb67dfa982affe0aac058f'
        '6e15864269b135418261fc3afb089472cf68c45dd7f231c6249ba0255e1e0338'
        '33fc4d00a3fe02132d7bc3873614b8aee34273581ea0325c81f0270affa13641'
        'd052d36f0757d484014354d02d6883ca15c24d8c3956b1bd027bcf41f151fd80'
        '23c5340e5606f37e90fdb87c86fb4fa634b3718a30bace06a66eaf8f63c4aa3b'
        '637826a87fe8cfa44282e92cb1615af3a28e53bc74c7cba1a0977be9065d0c1a'
        '5dec6c54ae38d37f37aa35283e048e5530a85c4e7a29d7b92ec0c3169cdf2a80'
        '5c7604bce60049b9fb7b8eaac10f51ae23794ceba68bb58112e293b9b692ca72'
        '1b37c662f8574ed4dba6f88e170881c82cddc1034a0ca7e284bf0962b6b26292'
        'd836fa9f73c1ac770eef0f2d3a1eaf61d3e03555fd424eedd67e18a18094f888',
      );
      var cipher = fromHex(
        'd55f684f81f4426e9fde92a5ff02df2ac896af63962888a97910c1379e20b0a3'
        'b1db613fb7fe2e07004329ea5c22bfd33e3dbe4cf58cc608c2c26c19a2e2fe22'
        'f98732c2b5cb844cc6c0702d91e1d50fc4382a7eba5635cd602432a2306ac4ce'
        '82f8d70c8d9bc15f918fe71e74c622d5cf71178bf6e0b9cc9f2b41dd8dbe441c'
        '41cd0c73a6dc47a348f6702f9d0e9b1b1431e948e299b9ec2272ab2c5f0c7be8'
        '6affa5dec87a0bee81d3d50007edaa2bcfccb35605155ff36ed8edd4a40dcd4b'
        '243acd11b2b987bdbfaf91a7cac27e9c5aea525ee53de7b2d3332c8644402b82'
        '3e94a7db26276d2d23aa07180f76b4fd29b9c0823099c9d62c519880aee7e969'
        '7617c1497d47bf3e571950311421b6b734d38b0db91eb85331b91ea9f61530f5'
        '4512a5a52a4bad589eb69781d537f23297bb459bdad2948a29e1550bf4787e0b'
        'e95bb173cf5fab17dab7a13a052a63453d97ccec1a321954886b7a1299faaeec'
        'ae35c6eaaca753b041b5e5f093bf83397fd21dd6b3012066fcc058cc32c3b09d'
        '7562dee29509b5839392c9ff05f51f3166aaac4ac5f238038a3045e6f72e48ef'
        '0fe8bc675e82c318a268e43970271bf119b81bf6a982746554f84e72b9f00280'
        'a320a08142923c23c883423ff949827f29bbacdc1ccdb04938ce6098c95ba6b3'
        '2528f4ef78eed778b2e122ddfd1cbdd11d1c0a6783e011fc536d63d053260637',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 8', () {
      var key = fromHex(
        '27182818284590452353602874713526'
        '31415926535897932384626433832795',
      );
      var sector = Nonce64.int32(0xfe);
      var plain = fromHex(
        'd55f684f81f4426e9fde92a5ff02df2ac896af63962888a97910c1379e20b0a3'
        'b1db613fb7fe2e07004329ea5c22bfd33e3dbe4cf58cc608c2c26c19a2e2fe22'
        'f98732c2b5cb844cc6c0702d91e1d50fc4382a7eba5635cd602432a2306ac4ce'
        '82f8d70c8d9bc15f918fe71e74c622d5cf71178bf6e0b9cc9f2b41dd8dbe441c'
        '41cd0c73a6dc47a348f6702f9d0e9b1b1431e948e299b9ec2272ab2c5f0c7be8'
        '6affa5dec87a0bee81d3d50007edaa2bcfccb35605155ff36ed8edd4a40dcd4b'
        '243acd11b2b987bdbfaf91a7cac27e9c5aea525ee53de7b2d3332c8644402b82'
        '3e94a7db26276d2d23aa07180f76b4fd29b9c0823099c9d62c519880aee7e969'
        '7617c1497d47bf3e571950311421b6b734d38b0db91eb85331b91ea9f61530f5'
        '4512a5a52a4bad589eb69781d537f23297bb459bdad2948a29e1550bf4787e0b'
        'e95bb173cf5fab17dab7a13a052a63453d97ccec1a321954886b7a1299faaeec'
        'ae35c6eaaca753b041b5e5f093bf83397fd21dd6b3012066fcc058cc32c3b09d'
        '7562dee29509b5839392c9ff05f51f3166aaac4ac5f238038a3045e6f72e48ef'
        '0fe8bc675e82c318a268e43970271bf119b81bf6a982746554f84e72b9f00280'
        'a320a08142923c23c883423ff949827f29bbacdc1ccdb04938ce6098c95ba6b3'
        '2528f4ef78eed778b2e122ddfd1cbdd11d1c0a6783e011fc536d63d053260637',
      );
      var cipher = fromHex(
        '72efc1ebfe1ee25975a6eb3aa8589dda2b261f1c85bdab442a9e5b2dd1d7c395'
        '7a16fc08e526d4b1223f1b1232a11af274c3d70dac57f83e0983c498f1a6f1ae'
        'cb021c3e70085a1e527f1ce41ee5911a82020161529cd82773762daf5459de94'
        'a0a82adae7e1703c808543c29ed6fb32d9e004327c1355180c995a07741493a0'
        '9c21ba01a387882da4f62534b87bb15d60d197201c0fd3bf30c1500a3ecfecdd'
        '66d8721f90bcc4c17ee925c61b0a03727a9c0d5f5ca462fbfa0af1c2513a9d9d'
        '4b5345bd27a5f6e653f751693e6b6a2b8ead57d511e00e58c45b7b8d005af792'
        '88f5c7c22fd4f1bf7a898b03a5634c6a1ae3f9fae5de4f296a2896b23e7ed43e'
        'd14fa5a2803f4d28f0d3ffcf24757677aebdb47bb388378708948a8d4126ed18'
        '39e0da29a537a8c198b3c66ab00712dd261674bf45a73d67f76914f830ca014b'
        '65596f27e4cf62de66125a5566df9975155628b400fbfb3a29040ed50faffdbb'
        '18aece7c5c44693260aab386c0a37b11b114f1c415aebb653be468179428d43a'
        '4d8bc3ec38813eca30a13cf1bb18d524f1992d44d8b1a42ea30b22e6c95b199d'
        '8d182f8840b09d059585c31ad691fa0619ff038aca2c39a943421157361717c4'
        '9d322028a74648113bd8c9d7ec77cf3c89c1ec8718ceff8516d96b34c3c614f1'
        '0699c9abc4ed0411506223bea16af35c883accdbe1104eef0cfdb54e12fb230a',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 9', () {
      var key = fromHex(
        '27182818284590452353602874713526'
        '31415926535897932384626433832795',
      );
      var sector = Nonce64.int32(0xff);
      var plain = fromHex(
        '72efc1ebfe1ee25975a6eb3aa8589dda2b261f1c85bdab442a9e5b2dd1d7c395'
        '7a16fc08e526d4b1223f1b1232a11af274c3d70dac57f83e0983c498f1a6f1ae'
        'cb021c3e70085a1e527f1ce41ee5911a82020161529cd82773762daf5459de94'
        'a0a82adae7e1703c808543c29ed6fb32d9e004327c1355180c995a07741493a0'
        '9c21ba01a387882da4f62534b87bb15d60d197201c0fd3bf30c1500a3ecfecdd'
        '66d8721f90bcc4c17ee925c61b0a03727a9c0d5f5ca462fbfa0af1c2513a9d9d'
        '4b5345bd27a5f6e653f751693e6b6a2b8ead57d511e00e58c45b7b8d005af792'
        '88f5c7c22fd4f1bf7a898b03a5634c6a1ae3f9fae5de4f296a2896b23e7ed43e'
        'd14fa5a2803f4d28f0d3ffcf24757677aebdb47bb388378708948a8d4126ed18'
        '39e0da29a537a8c198b3c66ab00712dd261674bf45a73d67f76914f830ca014b'
        '65596f27e4cf62de66125a5566df9975155628b400fbfb3a29040ed50faffdbb'
        '18aece7c5c44693260aab386c0a37b11b114f1c415aebb653be468179428d43a'
        '4d8bc3ec38813eca30a13cf1bb18d524f1992d44d8b1a42ea30b22e6c95b199d'
        '8d182f8840b09d059585c31ad691fa0619ff038aca2c39a943421157361717c4'
        '9d322028a74648113bd8c9d7ec77cf3c89c1ec8718ceff8516d96b34c3c614f1'
        '0699c9abc4ed0411506223bea16af35c883accdbe1104eef0cfdb54e12fb230a',
      );
      var cipher = fromHex(
        '3260ae8dad1f4a32c5cafe3ab0eb95549d461a67ceb9e5aa2d3afb62dece0553'
        '193ba50c75be251e08d1d08f1088576c7efdfaaf3f459559571e12511753b07a'
        'f073f35da06af0ce0bbf6b8f5ccc5cea500ec1b211bd51f63b606bf6528796ca'
        '12173ba39b8935ee44ccce646f90a45bf9ccc567f0ace13dc2d53ebeedc81f58'
        'b2e41179dddf0d5a5c42f5d8506c1a5d2f8f59f3ea873cbcd0eec19acbf32542'
        '3bd3dcb8c2b1bf1d1eaed0eba7f0698e4314fbeb2f1566d1b9253008cbccf45a'
        '2b0d9c5c9c21474f4076e02be26050b99dee4fd68a4cf890e496e4fcae7b70f9'
        '4ea5a9062da0daeba1993d2ccd1dd3c244b8428801495a58b216547e7e847c46'
        'd1d756377b6242d2e5fb83bf752b54e0df71e889f3a2bb0f4c10805bf3c59037'
        '6e3c24e22ff57f7fa965577375325cea5d920db94b9c336b455f6e894c01866f'
        'e9fbb8c8d3f70a2957285f6dfb5dcd8cbf54782f8fe7766d4723819913ac7734'
        '21e3a31095866bad22c86a6036b2518b2059b4229d18c8c2ccbdf906c6cc6e82'
        '464ee57bddb0bebcb1dc645325bfb3e665ef7251082c88ebb1cf203bd779fdd3'
        '8675713c8daadd17e1cabee432b09787b6ddf3304e38b731b45df5df51b78fcf'
        'b3d32466028d0ba36555e7e11ab0ee0666061d1645d962444bc47a38188930a8'
        '4b4d561395c73c087021927ca638b7afc8a8679ccb84c26555440ec7f10445cd',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 10', () {
      var key = fromHex(
        '2718281828459045235360287471352662497757247093699959574966967627'
        '3141592653589793238462643383279502884197169399375105820974944592',
      );
      var sector = Nonce64.int32(0xff);
      var plain = fromHex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      );
      var cipher = fromHex(
        '1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b'
        '5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd'
        '5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0'
        'c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca'
        '2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0'
        'b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f'
        '93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec'
        '583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a'
        '84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1'
        '505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae'
        '9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29'
        'a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac'
        '6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f'
        '645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385'
        '1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa'
        '773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 11', () {
      var key = fromHex(
        '2718281828459045235360287471352662497757247093699959574966967627'
        '3141592653589793238462643383279502884197169399375105820974944592',
      );
      var sector = Nonce64.int32(0xffff);
      var plain = fromHex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      );
      var cipher = fromHex(
        '77a31251618a15e6b92d1d66dffe7b50b50bad552305ba0217a610688eff7e11'
        'e1d0225438e093242d6db274fde801d4cae06f2092c728b2478559df58e837c2'
        '469ee4a4fa794e4bbc7f39bc026e3cb72c33b0888f25b4acf56a2a9804f1ce6d'
        '3d6e1dc6ca181d4b546179d55544aa7760c40d06741539c7e3cd9d2f6650b201'
        '3fd0eeb8c2b8e3d8d240ccae2d4c98320a7442e1c8d75a42d6e6cfa4c2eca179'
        '8d158c7aecdf82490f24bb9b38e108bcda12c3faf9a21141c3613b58367f922a'
        'aa26cd22f23d708dae699ad7cb40a8ad0b6e2784973dcb605684c08b8d6998c6'
        '9aac049921871ebb65301a4619ca80ecb485a31d744223ce8ddc2394828d6a80'
        '470c092f5ba413c3378fa6054255c6f9df4495862bbb3287681f931b687c888a'
        'bf844dfc8fc28331e579928cd12bd2390ae123cf03818d14dedde5c0c24c8ab0'
        '18bfca75ca096f2d531f3d1619e785f1ada437cab92e980558b3dce1474afb75'
        'bfedbf8ff54cb2618e0244c9ac0d3c66fb51598cd2db11f9be39791abe447c63'
        '094f7c453b7ff87cb5bb36b7c79efb0872d17058b83b15ab0866ad8a58656c5a'
        '7e20dbdf308b2461d97c0ec0024a2715055249cf3b478ddd4740de654f75ca68'
        '6e0d7345c69ed50cdc2a8b332b1f8824108ac937eb050585608ee734097fc090'
        '54fbff89eeaeea791f4a7ab1f9868294a4f9e27b42af8100cb9d59cef9645803',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 12', () {
      var key = fromHex(
        '2718281828459045235360287471352662497757247093699959574966967627'
        '3141592653589793238462643383279502884197169399375105820974944592',
      );
      var sector = Nonce64.hex('ffffff');
      var plain = fromHex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      );
      var cipher = fromHex(
        'e387aaa58ba483afa7e8eb469778317ecf4cf573aa9d4eac23f2cdf914e4e200'
        'a8b490e42ee646802dc6ee2b471b278195d60918ececb44bf79966f83faba049'
        '9298ebc699c0c8634715a320bb4f075d622e74c8c932004f25b41e361025b5a8'
        '7815391f6108fc4afa6a05d9303c6ba68a128a55705d415985832fdeaae6c8e1'
        '9110e84d1b1f199a2692119edc96132658f09da7c623efcec712537a3d94c0bf'
        '5d7e352ec94ae5797fdb377dc1551150721adf15bd26a8efc2fcaad56881fa9e'
        '62462c28f30ae1ceaca93c345cf243b73f542e2074a705bd2643bb9f7cc79bb6'
        'e7091ea6e232df0f9ad0d6cf502327876d82207abf2115cdacf6d5a48f6c1879'
        'a65b115f0f8b3cb3c59d15dd8c769bc014795a1837f3901b5845eb491adfefe0'
        '97b1fa30a12fc1f65ba22905031539971a10f2f36c321bb51331cdefb39e3964'
        'c7ef079994f5b69b2edd83a71ef549971ee93f44eac3938fcdd61d01fa71799d'
        'a3a8091c4c48aa9ed263ff0749df95d44fef6a0bb578ec69456aa5408ae32c7a'
        'f08ad7ba8921287e3bbee31b767be06a0e705c864a769137df28292283ea81a2'
        '480241b44d9921cdbec1bc28dc1fda114bd8e5217ac9d8ebafa720e9da4f9ace'
        '231cc949e5b96fe76ffc21063fddc83a6b8679c00d35e09576a875305bed5f36'
        'ed242c8900dd1fa965bc950dfce09b132263a1eef52dd6888c309f5a7d712826',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 13', () {
      var key = fromHex(
        '2718281828459045235360287471352662497757247093699959574966967627'
        '3141592653589793238462643383279502884197169399375105820974944592',
      );
      var sector = Nonce64.hex('ffffffff');
      var plain = fromHex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      );
      var cipher = fromHex(
        'bf53d2dade78e822a4d949a9bc6766b01b06a8ef70d26748c6a7fc36d80ae4c5'
        '520f7c4ab0ac8544424fa405162fef5a6b7f229498063618d39f0003cb5fb8d1'
        'c86b643497da1ff945c8d3bedeca4f479702a7a735f043ddb1d6aaade3c4a0ac'
        '7ca7f3fa5279bef56f82cd7a2f38672e824814e10700300a055e1630b8f1cb0e'
        '919f5e942010a416e2bf48cb46993d3cb6a51c19bacf864785a00bc2ecff15d3'
        '50875b246ed53e68be6f55bd7e05cfc2b2ed6432198a6444b6d8c247fab941f5'
        '69768b5c429366f1d3f00f0345b96123d56204c01c63b22ce78baf116e525ed9'
        '0fdea39fa469494d3866c31e05f295ff21fea8d4e6e13d67e47ce722e9698a1c'
        '1048d68ebcde76b86fcf976eab8aa9790268b7068e017a8b9b749409514f1053'
        '027fd16c3786ea1bac5f15cb79711ee2abe82f5cf8b13ae73030ef5b9e4457e7'
        '5d1304f988d62dd6fc4b94ed38ba831da4b7634971b6cd8ec325d9c61c00f1df'
        '73627ed3745a5e8489f3a95c69639c32cd6e1d537a85f75cc844726e8a72fc00'
        '77ad22000f1d5078f6b866318c668f1ad03d5a5fced5219f2eabbd0aa5c0f460'
        'd183f04404a0d6f469558e81fab24a167905ab4c7878502ad3e38fdbe62a4155'
        '6cec37325759533ce8f25f367c87bb5578d667ae93f9e2fd99bcbc5f2fbba88c'
        'f6516139420fcff3b7361d86322c4bd84c82f335abb152c4a93411373aaa8220',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 14', () {
      var key = fromHex(
        '2718281828459045235360287471352662497757247093699959574966967627'
        '3141592653589793238462643383279502884197169399375105820974944592',
      );
      var sector = Nonce64.hex('ffffffffff');
      var plain = fromHex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      );
      var cipher = fromHex(
        '64497e5a831e4a932c09be3e5393376daa599548b816031d224bbf50a818ed23'
        '50eae7e96087c8a0db51ad290bd00c1ac1620857635bf246c176ab463be30b80'
        '8da548081ac847b158e1264be25bb0910bbc92647108089415d45fab1b3d2604'
        'e8a8eff1ae4020cfa39936b66827b23f371b92200be90251e6d73c5f86de5fd4'
        'a950781933d79a28272b782a2ec313efdfcc0628f43d744c2dc2ff3dcb66999b'
        '50c7ca895b0c64791eeaa5f29499fb1c026f84ce5b5c72ba1083cddb5ce45434'
        '631665c333b60b11593fb253c5179a2c8db813782a004856a1653011e93fb6d8'
        '76c18366dd8683f53412c0c180f9c848592d593f8609ca736317d356e13e2bff'
        '3a9f59cd9aeb19cd482593d8c46128bb32423b37a9adfb482b99453fbe25a41b'
        'f6feb4aa0bef5ed24bf73c762978025482c13115e4015aac992e5613a3b5c2f6'
        '85b84795cb6e9b2656d8c88157e52c42f978d8634c43d06fea928f2822e465aa'
        '6576e9bf419384506cc3ce3c54ac1a6f67dc66f3b30191e698380bc999b05abc'
        'e19dc0c6dcc2dd001ec535ba18deb2df1a101023108318c75dc98611a09dc48a'
        '0acdec676fabdf222f07e026f059b672b56e5cbc8e1d21bbd867dd9272120546'
        '81d70ea737134cdfce93b6f82ae22423274e58a0821cc5502e2d0ab4585e94de'
        '6975be5e0b4efce51cd3e70c25a1fbbbd609d273ad5b0d59631c531f6a0a57b9',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    // NOTE: Vector 15-19 are faulty. Using python Cryptography output below
  });

  group('Python Cryptography output', () {
    // Following test cases are from
    // https://crossbowerbt.github.io/docs/crypto/pdf00086.pdf
    group('Vector 15', () {
      var key = fromHex(
        'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'
        'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0',
      );
      var sector = Nonce64.hex(
        '9a78563412',
      );
      var plain = fromHex(
        '000102030405060708090a0b0c0d0e0f10',
      );
      var cipher = fromHex(
        '6c1625db4671522d3d7599601de7ca09ed',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 16', () {
      var key = fromHex(
        'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'
        'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0',
      );
      var sector = Nonce64.hex(
        '9a78563412',
      );
      var plain = fromHex(
        '000102030405060708090a0b0c0d0e0f1011',
      );
      var cipher = fromHex(
        'd069444b7a7e0cab09e24447d24deb1fedbf',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 17', () {
      var key = fromHex(
        'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'
        'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0',
      );
      var sector = Nonce64.hex(
        '9a78563412',
      );
      var plain = fromHex(
        '000102030405060708090a0b0c0d0e0f101112',
      );
      var cipher = fromHex(
        'e5df1351c0544ba1350b3363cd8ef4beedbf9d',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 18', () {
      var key = fromHex(
        'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'
        'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0',
      );
      var sector = fromHex(
        '123456789a0000000000000000000000',
      );
      var plain = fromHex(
        '000102030405060708090a0b0c0d0e0f10111213',
      );
      var cipher = fromHex(
        'a8ba0048d75084603eb8423a09b7bf7595c871f6',
      );
      var aes = AES(key).xts(sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('Vector 19', () {
      var key = fromHex(
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
      );
      var sector = Nonce64.hex(
        '21436587a9',
      );
      var plain = fromHex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f'
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      );
      var cipher = fromHex(
        '38b45812ef43a05bd957e545907e223b954ab4aaf088303ad910eadf14b42be6'
        '8b2461149d8c8ba85f992be970bc621f1b06573f63e867bf5875acafa04e42cc'
        'bd7bd3c2a0fb1fff791ec5ec36c66ae4ac1e806d81fbf709dbe29e471fad3854'
        '9c8e66f5345d7c1eb94f405d1ec785cc6f6a68f6254dd8339f9d84057e01a177'
        '41990482999516b5611a38f41bb6478e6f173f320805dd71b1932fc333cb9ee3'
        '9936beea9ad96fa10fb4112b901734ddad40bc1878995f8e11aee7d141a2f5d4'
        '8b7a4e1e7f0b2c04830e69a4fd1378411c2f287edf48c6c4e5c247a19680f7fe'
        '41cefbd49b582106e3616cbbe4dfb2344b2ae9519391f3e0fb4922254b1d6d2d'
        '19c6d4d537b3a26f3bcc51588b32f3eca0829b6a5ac72578fb814fb43cf80d64'
        'a233e3f997a3f02683342f2b33d25b492536b93becb2f5e1a8b82f5b88334272'
        '9e8ae09d16938841a21a97fb543eea3bbff59f13c1a18449e398701c1ad51648'
        '346cbc04c27bb2da3b93a1372ccae548fb53bee476f9e9c91773b1bb19828394'
        'd55d3e1a20ed69113a860b6829ffa847224604435070221b257e8dff783615d2'
        'cae4803a93aa4334ab482a0afac9c0aeda70b45a481df5dec5df8cc0f423c77a'
        '5fd46cd312021d4b438862419a791be03bb4d97c0e59578542531ba466a83baf'
        '92cefc151b5cc1611a167893819b63fb8a6b18e86de60290fa72b797b0ce59f3',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
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

  // https://csrc.nist.rip/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/XTSTestVectors.zip
  group('NIST XTSTestVectors | AES128 Encrypt with sector value', () {
    group('COUNT = 1 | DataUnitLen = 128', () {
      var key = fromHex(
        'a3e40d5bd4b6bbedb2d18c700ad2db2210c81190646d673cbca53f133eab373c',
      );
      var sector = Nonce64.int32(141);
      var plain = fromHex(
        '20e0719405993f09a66ae5bb500e562c',
      );
      var cipher = fromHex(
        '74623551210216ac926b9650b6d3fa52',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 37 | DataUnitLen = 128', () {
      var key = fromHex(
        '5f14eee6952c8a4c2d55fb694a5b70a4b6ad43cfe603dec092a9696d5c24863e',
      );
      var sector = Nonce64.int32(250);
      var plain = fromHex(
        '8d88813f3a975a64d4db6f024417e3e7',
      );
      var cipher = fromHex(
        '0ff526fcf20c2e8356cfe7f26fbebef4',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 101 | DataUnitLen = 256', () {
      var key = fromHex(
        '69438582e0a61b5e7a023adf2f419630ed537ccf9a4b2e09010eaf7b66bcf818',
      );
      var sector = Nonce64.int32(232);
      var plain = fromHex(
        '05c2c05e812bc4295f3ef64c8bc468ee946176449edc481785e6c6d9fbdd6b8f',
      );
      var cipher = fromHex(
        '27259ec330a66591e265525cd1eb5017ba195a390e4f66ddfb7c1a4b0fb5e49d',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 196 | DataUnitLen = 256', () {
      var key = fromHex(
        'd4b06bbbb1b088a0699e3cc9f05c859317980660c54002d0308adb5d012eb4d9',
      );
      var sector = Nonce64.int32(75);
      var plain = fromHex(
        'af6e3c9bea494cfc633f631b73119f00cab9a98ddc2197ee69d61d38df25619c',
      );
      var cipher = fromHex(
        'ad6f759f80d4e4af0bc583358cbca1873065227ab1b307f3e9a774f3ce5c6b63',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 301 | DataUnitLen = 200', () {
      var key = fromHex(
        'fb46fb3cab7f67ad5207bc232c50dcbb24dbd1564590855d4cb777b3ba6431c3',
      );
      var sector = Nonce64.int32(117);
      var plain = fromHex(
        '46409f7426eb4e3d33480534b80fe6e09fed6583907eb83c84',
      );
      var cipher = fromHex(
        'a19d9b3209d388740a581975091fe26deecbb0f117c22b0ae4',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 330 | DataUnitLen = 200', () {
      var key = fromHex(
        '546923c3625a11451aec09a8cdf874ecb88c776dd19e715ea5d187ebb648627c',
      );
      var sector = Nonce64.int32(2);
      var plain = fromHex(
        'b2a5efdf30c4a376d1f699d6a1ca59b8f49913693ee604f4cd',
      );
      var cipher = fromHex(
        'df717b4636ecfd469ea9b4c0c0689a7cdd6a0650a9df448887',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 358 | DataUnitLen = 200', () {
      var key = fromHex(
        'dd9f8a86307bd905f90c676c46f13c42843587b54df3d74d4f3d07382e1bbdd3',
      );
      var sector = Nonce64.int32(244);
      var plain = fromHex(
        'e3526fca52a747dc7487b6a6c399e8b8b4cb29e941ec37f3ea',
      );
      var cipher = fromHex(
        '35485a0f1a7e0f95dedb63041637bcbaad2662111265923442',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 405 | DataUnitLen = 256', () {
      var key = fromHex(
        '0b38e36b4df66300aa217a0278874f60ada795fcfb444b17eb0a93beeee92df6',
      );
      var sector = Nonce64.int32(60);
      var plain = fromHex(
        'b66118af7cede3318ed763045db7451fc7d337bba7d280f53c38bf3084d348a4',
      );
      var cipher = fromHex(
        'd8903be9806a9056c05356b7760f078401fab76fc8d264b2dd2688a29bb5eea6',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 499 | DataUnitLen = 256', () {
      var key = fromHex(
        'ed407618358c48f225a8fab5f62fa3857b996d5c6dd909d062f9c15cbdb09c0a',
      );
      var sector = Nonce64.int32(128);
      var plain = fromHex(
        '417ff7b4f6df391682006f6a48c11658e57450782e00fd6f5565e61a5263d50e',
      );
      var cipher = fromHex(
        'e950eb1286c77c848d981c9b8958eb590af5642b799e4895f4a3ff1e25a5abff',
      );
      var aes = AESInXTSMode.fromSector(key, sector);
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

  group('NIST XTSTestVectors | AES128 Encrypt with Tweak value', () {
    group('COUNT = 1 | DataUnitLen = 128', () {
      var key = fromHex(
        'a1b90cba3f06ac353b2c343876081762090923026e91771815f29dab01932f2f',
      );
      var tweak = fromHex(
        '4faef7117cda59c66e4b92013e768ad5',
      );
      var plain = fromHex(
        'ebabce95b14d3c8d6fb350390790311c',
      );
      var cipher = fromHex(
        '778ae8b43cb98d5a825081d5be471c63',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 50 | DataUnitLen = 128', () {
      var key = fromHex(
        '5ad0f03fbca7f0d6551d94c1faf9d329f025068ced476d72d91ab22cc3c05449',
      );
      var tweak = fromHex(
        '7c9e49f219189a3fbe991fa8f83cda5b',
      );
      var plain = fromHex(
        '946dfefe5aadce492b3875ce3409b0c0',
      );
      var cipher = fromHex(
        '62bc8ce1873a54c70bba35014877873e',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 101 | DataUnitLen = 256', () {
      var key = fromHex(
        'b7b93f516aef295eff3a29d837cf1f135347e8a21dae616ff5062b2e8d78ce5e',
      );
      var tweak = fromHex(
        '873edea653b643bd8bcf51403197ed14',
      );
      var plain = fromHex(
        '236f8a5b58dd55f6194ed70c4ac1a17f1fe60ec9a6c454d087ccb77d6b638c47',
      );
      var cipher = fromHex(
        '22e6a3c6379dcf7599b052b5a749c7f78ad8a11b9f1aa9430cf3aef445682e19',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 151 | DataUnitLen = 256', () {
      var key = fromHex(
        'a9e399b4568aaec4474baeceea77a8e715ae94694c30aff32be0353734f0a25d',
      );
      var tweak = fromHex(
        'd52c178b397287d447874474da7f97a2',
      );
      var plain = fromHex(
        'c774446d56bbc44e376e490f55f9f00308e4df157940e590c61780638f0dd134',
      );
      var cipher = fromHex(
        '810d2031aa28959210231e7b0ea4e00e0de4476ee5c7b138ecaf65a1099630cb',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 301 | DataUnitLen = 200', () {
      var key = fromHex(
        '394c97881abd989d29c703e48a72b397a7acf51b59649eeea9b33274d8541df4',
      );
      var tweak = fromHex(
        '4b15c684a152d485fe9937d39b168c29',
      );
      var plain = fromHex(
        '2f3b9dcfbae729583b1d1ffdd16bb6fe2757329435662a78f0',
      );
      var cipher = fromHex(
        'f3473802e38a3ffef4d4fb8e6aa266ebde553a64528a06463e',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 351 | DataUnitLen = 200', () {
      var key = fromHex(
        'e764d4a43c23500302f3cce9f4d78a922f31e822e68c41be20efd3c981eb4e9b',
      );
      var tweak = fromHex(
        '11ce717ef2e553c32f0cc16cb0d4b0e6',
      );
      var plain = fromHex(
        '14962b52355600e138d3bebe594ae85c96c5027a6d65887c01',
      );
      var cipher = fromHex(
        '41f829f09977f4724d4c1fe387b7ea0135918d61d6c24aaa81',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 401 | DataUnitLen = 256', () {
      var key = fromHex(
        '03877591c280ac961c7a934f983121053695610f32e58a936a85a0a646f54eea',
      );
      var tweak = fromHex(
        '5f193c539893edcea422e1c9d01ad95e',
      );
      var plain = fromHex(
        '83280dfecb3480491ac2df2ec90953e81f1e1ebc7659ec9820acb8eb8ce030cf',
      );
      var cipher = fromHex(
        'f491446e42f9ccab200ecb505f7e49bf8a2ec66d4ea9420858c04544a4221bf8',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 451 | DataUnitLen = 256', () {
      var key = fromHex(
        'f6da105bf2cb3c17b08127e72aa7e5a1d71f59dcb7272e6e3d397dc49ce3baa4',
      );
      var tweak = fromHex(
        '20b6f7eee88a0305edd2d3cb832456c2',
      );
      var plain = fromHex(
        '7436a5cdb44fba8e9870316276f6b0889de65d122a657ad2346144cadb427a5c',
      );
      var cipher = fromHex(
        '95a17741dd4717c08299988135bf8ffddf042bb89cbed4a106254a9b8be3ce71',
      );
      var aes = AES(key).xts(tweak);
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

  group('NIST XTSTestVectors | AES256 Encrypt with Tweak value', () {
    group('COUNT = 1 | DataUnitLen = 256', () {
      var key = fromHex(
        '1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7cd6e13ffdf2418d8d1911c004cda58da3d619b7e2b9141e58318eea392cf41b08',
      );
      var tweak = fromHex(
        'adf8d92627464ad2f0428e84a9f87564',
      );
      var plain = fromHex(
        '2eedea52cd8215e1acc647e810bbc3642e87287f8d2e57e36c0a24fbc12a202e',
      );
      var cipher = fromHex(
        'cbaad0e2f6cea3f50b37f934d46a9b130b9d54f07e34f36af793e86f73c6d7db',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 51 | DataUnitLen = 256', () {
      var key = fromHex(
        'bd3e3a102cac0a692e72b5c3529b0fcea279d8588ed3c5fa3018ba672c12cfe07a58cd95e037b55b2d621b6791f4abbc7a5d9a7c112ac7c7871dcbba57c06c87',
      );
      var tweak = fromHex(
        '5dbfa92072870ae6b02da840f272de16',
      );
      var plain = fromHex(
        '39069d88e51c26432ddb0ec8da3af3b53f0f71411e1434e87274f9eb540047b4',
      );
      var cipher = fromHex(
        '969d42664562fe21c6e158c537493fb154202cd741676747c239749ebf46bb34',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 101 | DataUnitLen = 384', () {
      var key = fromHex(
        '266c336b3b01489f3267f52835fd92f674374b88b4e1ebd2d36a5f457581d9d042c3eef7b0b7e5137b086496b4d9e6ac658d7196a23f23f036172fdb8faee527',
      );
      var tweak = fromHex(
        '06b209a7a22f486ecbfadb0f3137ba42',
      );
      var plain = fromHex(
        'ca7d65ef8d3dfad345b61ccddca1ad81de830b9e86c7b426d76cb7db766852d981c6b21409399d78f42cc0b33a7bbb06',
      );
      var cipher = fromHex(
        'c73256870cc2f4dd57acc74b5456dbd776912a128bc1f77d72cdebbf270044b7a43ceed29025e1e8be211fa3c3ed002d',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 151 | DataUnitLen = 384', () {
      var key = fromHex(
        '3655b75c8622b0cb72fcf91adda8584d24854abec01edf3311e4ec760dcdaa21f8088acdfc493b0bcdf486f1419b48662eeca09c5f87c9cf8416f7b0c021ddb2',
      );
      var tweak = fromHex(
        '445d7f431d12e1550a1d74d9fd3e5334',
      );
      var plain = fromHex(
        '9c8e67abac7191f52f761c1ce7df0f383471825a9d0f0c8a890fccea0bfee4d2643275237440761517e1599e736bb35f',
      );
      var cipher = fromHex(
        '42bc46ab27c0ff1a3512267e7a72868f4e268f2da85fd42755011345b8f0c7fd7d82c1dffe78a787bcd1eae7ead24f69',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 401 | DataUnitLen = 384', () {
      var key = fromHex(
        '33e89e817ff8d037d6ac5a2296657503f20885d94c483e26449066bd9284d1302dbdbb4b66b6b9f4687f13dd028eb6aa528ca91deb9c5f40db93218806033801',
      );
      var tweak = fromHex(
        'a78c04335ab7498a52b81ed74b48e6cf',
      );
      var plain = fromHex(
        '14c3ac31291b075f40788247c3019e88c7b40bac3832da45bbc6c4fe7461371b4dfffb63f71c9f8edb98f28ff4f33121',
      );
      var cipher = fromHex(
        'dead7e587519bc78c70d99279fbe3d9b1ad13cdaae69824e0ab8135413230bfdb13babe8f986fbb30d46ab5ec56b916e',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 451 | DataUnitLen = 384', () {
      var key = fromHex(
        '94567a4abf8616ad67bee70cc9a4efabf81a7ded305db095a08d401176a4b218a31ec1e922ff386a80266e1d369e785d8c1378addb65116581d01119e41ec144',
      );
      var tweak = fromHex(
        '0f7d9ca5d875bdeddc368c3308a44170',
      );
      var plain = fromHex(
        'e1c2c4283348f591ad59dd9514b3b51bade71135785d79927dba1630fafdbbba61f384a362ebaa7ac530acf3cf12ea15',
      );
      var cipher = fromHex(
        'c3f4026b886f91a2ef908ce80bc0642493c5fc71ffb426be688ad9cdc0e7ad83a0da7503a464b0fa8baf41ee61143fff',
      );
      var aes = AES(key).xts(tweak);
      test('encrypt', () {
        var actual = aes.encrypt(plain);
        expect(toHex(actual), equals(toHex(cipher)));
      });
      test('decrypt', () {
        var reverse = aes.decrypt(cipher);
        expect(toHex(reverse), equals(toHex(plain)));
      });
    });
    group('COUNT = 451 | DataUnitLen = 384', () {
      var key = fromHex(
        '94567a4abf8616ad67bee70cc9a4efabf81a7ded305db095a08d401176a4b218a31ec1e922ff386a80266e1d369e785d8c1378addb65116581d01119e41ec144',
      );
      var tweak = fromHex(
        '0f7d9ca5d875bdeddc368c3308a44170',
      );
      var plain = fromHex(
        'e1c2c4283348f591ad59dd9514b3b51bade71135785d79927dba1630fafdbbba61f384a362ebaa7ac530acf3cf12ea15',
      );
      var cipher = fromHex(
        'c3f4026b886f91a2ef908ce80bc0642493c5fc71ffb426be688ad9cdc0e7ad83a0da7503a464b0fa8baf41ee61143fff',
      );
      var aes = AES(key).xts(tweak);
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
      var key = randomBytes(32);
      for (int j = 16; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).xts(iv).encrypt(inp);
        var plain = AES(key).xts(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("192-bit", () {
      var key = randomBytes(48);
      for (int j = 16; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).xts(iv).encrypt(inp);
        var plain = AES(key).xts(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
    test("256-bit", () {
      var key = randomBytes(64);
      for (int j = 16; j < 100; j++) {
        var inp = randomBytes(j);
        var iv = randomBytes(16);
        var cipher = AES(key).xts(iv).encrypt(inp);
        var plain = AES(key).xts(iv).decrypt(cipher);
        expect(toHex(plain), equals(toHex(inp)), reason: '[size: $j]');
      }
    });
  });

  group('sink test', () {
    test('encryption', () {
      var key = randomBytes(32);
      for (int j = 16; j < 100; j++) {
        var iv = randomBytes(16);
        final aes = AES(key).xts(iv);

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
      for (int j = 16; j < 100; j++) {
        var iv = randomBytes(16);
        final aes = AES(key).xts(iv);

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
      for (int j = 16; j < 100; j++) {
        var iv = randomBytes(16);
        var input = randomBytes(j);

        final aes = AES(key).xts(iv);
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
}
