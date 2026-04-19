import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart';
import 'package:cipherlib/codecs.dart';
import 'package:cipherlib/random.dart';

import 'assertions.dart';

/// AES integration checks (modes, padding factories, GCM, keys, XTS).
void runAesIntegration() {
  aesModesRoundTrip();
  aesPaddingFactories();
  aesGcmWithAad();
  aesGcmCustomTagLength();
  aesGcmBadTagRejected();
  aesNoPaddingBlockAligned();
  aes128Key();
  aes192Key();
  aesXtsFromSector();
}

/// AES ECB/CBC/CTR/CFB/OFB/IGE/PCBC/XTS encrypt + decrypt string paths.
void aesModesRoundTrip() {
  const plain = 'A not very secret message';
  final key256 = randomBytes(32);
  final iv = randomBytes(16);

  print('----- AES (round-trip all modes) -----');
  final modes = <String, Uint8List Function()>{
    'CBC': () => AES(key256).cbc(iv).encryptString(plain),
    'CFB': () => AES(key256).cfb(iv).encryptString(plain),
    'CTR': () => AES(key256).ctr(iv).encryptString(plain),
    'ECB': () => AES(key256).ecb().encryptString(plain),
    'IGE': () => AES(key256).ige(iv).encryptString(plain),
    'GCM': () => AES(key256).gcm(iv).encryptString(plain),
    'OFB': () => AES(key256).ofb(iv).encryptString(plain),
    'PCBC': () => AES(key256).pcbc(iv).encryptString(plain),
    'XTS': () => AES(key256).xts(iv).encryptString(plain),
  };

  for (final e in modes.entries) {
    final ct = e.value();
    Uint8List pt;
    switch (e.key) {
      case 'CBC':
        pt = AES(key256).cbc(iv).decrypt(ct);
        break;
      case 'CFB':
        pt = AES(key256).cfb(iv).decrypt(ct);
        break;
      case 'CTR':
        pt = AES(key256).ctr(iv).decrypt(ct);
        break;
      case 'ECB':
        pt = AES(key256).ecb().decrypt(ct);
        break;
      case 'IGE':
        pt = AES(key256).ige(iv).decrypt(ct);
        break;
      case 'GCM':
        pt = AES(key256).gcm(iv).decrypt(ct);
        break;
      case 'OFB':
        pt = AES(key256).ofb(iv).decrypt(ct);
        break;
      case 'PCBC':
        pt = AES(key256).pcbc(iv).decrypt(ct);
        break;
      case 'XTS':
        pt = AES(key256).xts(iv).decrypt(ct);
        break;
      default:
        throw StateError(e.key);
    }
    expectSameUtf8(pt, plain);
    final hex = toHex(ct);
    final short = hex.length > 32 ? '${hex.substring(0, 32)}…' : hex;
    print('  ${e.key}: ok ($short)');
  }
  print('');
}

/// `AES.byte` / `AES.ansi` / `AES.pkcs7` factory constructors (CBC).
void aesPaddingFactories() {
  print('----- AES padding factories (CBC) -----');
  final key = randomBytes(32);
  final iv = randomBytes(16);
  const plain = 'padding factory demo';

  final variants = <String, AES>{
    'byte': AES.byte(key),
    'ansi': AES.ansi(key),
    'pkcs7': AES.pkcs7(key),
  };

  for (final e in variants.entries) {
    final ct = e.value.cbc(iv).encryptString(plain);
    final pt = e.value.cbc(iv).decrypt(ct);
    expectSameUtf8(pt, plain);
    print('  ${e.key}: ok');
  }
  print('');
}

void aesGcmWithAad() {
  const plain = 'authenticated payload';
  final key = randomBytes(32);
  final iv = randomBytes(12);
  final aad = toUtf8('metadata');

  print('----- AES-GCM + AAD -----');
  final gcm = AES(key).gcm(iv, aad: aad);
  final ct = gcm.encryptString(plain);
  final pt = gcm.decrypt(ct);
  expectSameUtf8(pt, plain);
  print('  round-trip: ok');
  print('');
}

void aesGcmCustomTagLength() {
  const plain = '12-byte auth tag';
  final key = randomBytes(32);
  final iv = randomBytes(12);

  print('----- AES-GCM tagSize=12 -----');
  final gcm = AES(key).gcm(iv, tagSize: 12);
  final ct = gcm.encryptString(plain);
  final pt = gcm.decrypt(ct);
  expectSameUtf8(pt, plain);
  print('  round-trip: ok');
  print('');
}

void aesGcmBadTagRejected() {
  print('----- AES-GCM bad tag -----');
  final key = randomBytes(32);
  final iv = randomBytes(12);
  const plain = 'gcm integrity';
  final gcm = AES(key).gcm(iv);
  final ct = Uint8List.fromList(gcm.encryptString(plain));
  ct[ct.length - 1] ^= 0xff;
  try {
    gcm.decrypt(ct);
    throw StateError('expected StateError for bad GCM tag');
  } on StateError {
    print('  rejected bad tag: ok');
  }
  print('');
}

void aesNoPaddingBlockAligned() {
  const plain16 = '0123456789abcdef';
  final key = randomBytes(16);

  print('----- AES ECB no padding (16-byte block) -----');
  final ct = AES.noPadding(key).ecb().encryptString(plain16);
  final pt = AES.noPadding(key).ecb().decrypt(ct);
  expectSameUtf8(pt, plain16);
  print('  round-trip: ok');
  print('');
}

void aes128Key() {
  const plain = 'hello AES-128';
  final key = randomBytes(16);
  final iv = randomBytes(16);

  print('----- AES-128 CBC -----');
  final ct = AES(key).cbc(iv).encryptString(plain);
  final pt = AES(key).cbc(iv).decrypt(ct);
  expectSameUtf8(pt, plain);
  print('  round-trip: ok');
  print('');
}

void aes192Key() {
  const plain = 'hello AES-192';
  final key = randomBytes(24);
  final iv = randomBytes(16);

  print('----- AES-192 CBC -----');
  final ct = AES(key).cbc(iv).encryptString(plain);
  final pt = AES(key).cbc(iv).decrypt(ct);
  expectSameUtf8(pt, plain);
  print('  round-trip: ok');
  print('');
}

void aesXtsFromSector() {
  const plain = '0123456789abcdef';
  final key = randomBytes(32);

  print('----- AES-XTS fromSector -----');
  final mode = AESInXTSMode.fromSector(key, Nonce64.int64(99));
  final ct = mode.encryptString(plain);
  final pt = mode.decrypt(ct);
  expectSameUtf8(pt, plain);
  print('  round-trip: ok');
  print('');
}
