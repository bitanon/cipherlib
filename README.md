# cipherlib

[![plugin version](https://img.shields.io/pub/v/cipherlib?label=pub)](https://pub.dev/packages/cipherlib)
[![test](https://github.com/bitanon/cipherlib/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/bitanon/cipherlib/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/bitanon/cipherlib/graph/badge.svg?token=ISIYJ8MNI0)](https://codecov.io/gh/bitanon/cipherlib)
[![likes](https://img.shields.io/pub/likes/cipherlib?logo=dart)](https://pub.dev/packages/cipherlib/score)
[![pub points](https://img.shields.io/pub/points/cipherlib?logo=dart&color=teal)](https://pub.dev/packages/cipherlib/score)
[![popularity](https://img.shields.io/pub/popularity/cipherlib?logo=dart)](https://pub.dev/packages/cipherlib/score)
[![dart support](https://img.shields.io/badge/dart-%3e%3d%202.14.0-39f?logo=dart)](https://dart.dev/guides/whats-new#september-8-2021-214-release)

Implementations of cryptographic algorithms for encryption and decryption in Dart.

## Depencencies

There are only 2 dependencies used by this package:

- [hashlib](https://pub.dev/packages/hashlib)
- [hashlib_codecs](https://pub.dev/packages/hashlib_codecs)

## Features

| Ciphers           | Public class and methods                                         |    Source     |
| ----------------- | ---------------------------------------------------------------- | :-----------: |
| AES               | `AES`,                                                           | NIST.FIPS.197 |
| XOR               | `XOR`, `xor`, `xorStream`                                        |   Wikipedia   |
| ChaCha20          | `ChaCha20`, `chacha20`, `chacha20Stream`                         |   RFC-8439    |
| ChaCha20/Poly1305 | `ChaCha20Poly1305`, `chacha20poly1305`, `chacha20poly1305Stream` |   RFC-8439    |
| Salsa20           | `Salsa20`, `salsa20`, `salsa20Stream`                            | Snuffle-2005  |
| Salsa20/Poly1305  | `Salsa20Poly1305`, `salsa20poly1305`, `salsa20poly1305Stream`    | Snuffle-2005  |

Available modes for AES:

- `ECB` : Electronic Codeblock
- `CBC` : Cipher Block Chaining
- `CTR` : Counter
- `GCM` : Galois/Counter Mode
- `CFB` : Cipher Feedback
- `OFB` : Output Feedback
- `IGE` : Infinite Garble Extension
- `PCBC` : Propagating Cipher Block Chaining
- `XTS` : XEX (XOR-Encrypt-XOR) Tweakable Block Cipher with Ciphertext Stealing

## Getting started

The following import will give you access to all of the algorithms in this package.

```dart
import 'package:cipherlib/cipherlib.dart';
```

Check the [API Reference](https://pub.dev/documentation/cipherlib/latest/cipherlib/cipherlib-library.html) for details.

## Usage

Examples can be found inside the `example` folder.

```dart
import 'package:cipherlib/cipherlib.dart';
import 'package:hashlib_codecs/hashlib_codecs.dart';

void main() {
  print('----- AES -----');
  {
    var plain = 'A not very secret message';
    var key = 'abcdefghijklmnopabcdefghijklmnop'.codeUnits;
    var iv = 'lka9JLKasljkdPsd'.codeUnits;
    print('  Text: $plain');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(iv)}');
    print('  ECB: ${toHex(AES(key).ecb().encryptString(plain))}');
    print('  CBC: ${toHex(AES(key).cbc(iv).encryptString(plain))}');
    print('  CTR: ${toHex(AES(key).ctr(iv).encryptString(plain))}');
    print('  GCM: ${toHex(AES(key).gcm(iv).encryptString(plain))}');
    print('  CFB: ${toHex(AES(key).cfb(iv).encryptString(plain))}');
    print('  OFB: ${toHex(AES(key).ofb(iv).encryptString(plain))}');
    print('  XTS: ${toHex(AES(key).xts(iv).encryptString(plain))}');
    print('  IGE: ${toHex(AES(key).ige(iv).encryptString(plain))}');
    print(' PCBC: ${toHex(AES(key).pcbc(iv).encryptString(plain))}');
  }
  print('');

  print('----- XOR -----');
  {
    var key = [0x54];
    var inp = [0x03, 0xF1];
    var cipher = xor(inp, key);
    var plain = xor(cipher, key);
    print('  Text: ${toBinary(inp)}');
    print('   Key: ${toBinary(key)}');
    print('   XOR: ${toBinary(cipher)}');
    print(' Plain: ${toBinary(plain)}');
  }
  print('');

  print('----- ChaCha20 -----');
  {
    var text = "Hide me!";
    var key = fromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    var nonce = fromHex("00000000000000004a000000");
    var res = chacha20poly1305(toUtf8(text), key, nonce: nonce);
    var plain = chacha20(res.data, key, nonce: nonce);
    print('  Text: $text');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(nonce)}');
    print('Cipher: ${toHex(res.data)}');
    print('   Tag: ${res.tag.hex()}');
    print(' Plain: ${fromUtf8(plain)}');
  }
  print('');

  print('----- Salsa20 -----');
  {
    var text = "Hide me!";
    var key = fromHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    var nonce = fromHex("00000000000000004a00000000000000");
    var res = salsa20poly1305(toUtf8(text), key, nonce: nonce);
    var plain = salsa20(res.data, key, nonce: nonce);
    print('  Text: $text');
    print('   Key: ${toHex(key)}');
    print(' Nonce: ${toHex(nonce)}');
    print('Cipher: ${toHex(res.data)}');
    print('   Tag: ${res.tag.hex()}');
    print(' Plain: ${fromUtf8(plain)}');
  }
}
```

# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib
- **PointyCastle** : https://pub.dev/packages/pointycastle
- **Cryptography** : https://pub.dev/packages/cryptography

With 1MB message (10 iterations):

| Algorithms        | `cipherlib`   | `PointyCastle`                | `cryptography`             |
| ----------------- | ------------- | ----------------------------- | -------------------------- |
| XOR               | **5.74 Gbps** |
| ChaCha20          | **1.21 Gbps** | 264 Mbps <br> `4.6x slow`     |                            |
| ChaCha20/Poly1305 | **765 Mbps**  | 194 Mbps <br> `3.94x slow`    | 289 Mbps <br> `2.65x slow` |
| Salsa20           | **1.23 Gbps** | 253 Mbps <br> `4.85x slow`    |                            |
| Salsa20/Poly1305  | **771 Mbps**  |                               |                            |
| AES-128/ECB       | **944 Mbps**  | 161 Mbps <br> `5.85x slow`    |                            |
| AES-192/ECB       | **853 Mbps**  | 145 Mbps <br> `5.88x slow`    |                            |
| AES-256/ECB       | **776 Mbps**  | 127 Mbps <br> `6.12x slow`    |                            |
| AES-128/CBC       | **964 Mbps**  | 157 Mbps <br> `6.14x slow`    | 859 Mbps <br> `1.12x slow` |
| AES-192/CBC       | **872 Mbps**  | 138 Mbps <br> `6.32x slow`    | 783 Mbps <br> `1.11x slow` |
| AES-256/CBC       | **793 Mbps**  | 123 Mbps <br> `6.46x slow`    | 712 Mbps <br> `1.11x slow` |
| AES-128/CTR       | **944 Mbps**  | 153 Mbps <br> `6.16x slow`    | 497 Mbps <br> `1.9x slow`  |
| AES-192/CTR       | **858 Mbps**  | 136 Mbps <br> `6.28x slow`    | 473 Mbps <br> `1.81x slow` |
| AES-256/CTR       | **781 Mbps**  | 121 Mbps <br> `6.48x slow`    | 449 Mbps <br> `1.74x slow` |
| AES-128/GCM       | **143 Mbps**  | 11.98 Mbps <br> `11.9x slow`  | 129 Mbps <br> `1.1x slow`  |
| AES-192/GCM       | **141 Mbps**  | 11.9 Mbps <br> `11.88x slow`  | 129 Mbps <br> `1.09x slow` |
| AES-256/GCM       | **139 Mbps**  | 11.75 Mbps <br> `11.86x slow` | 126 Mbps <br> `1.11x slow` |
| AES-128/CFB       | **453 Mbps**  | 658 kbps <br> `688.39x slow`  |                            |
| AES-192/CFB       | **416 Mbps**  | 661 kbps <br> `629.53x slow`  |                            |
| AES-256/CFB       | **378 Mbps**  | 659 kbps <br> `573.25x slow`  |                            |
| AES-128/OFB       | **807 Mbps**  | 155 Mbps <br> `5.19x slow`    |                            |
| AES-192/OFB       | **744 Mbps**  | 139 Mbps <br> `5.34x slow`    |                            |
| AES-256/OFB       | **678 Mbps**  | 124 Mbps <br> `5.47x slow`    |                            |
| AES-128/XTS       | **667 Mbps**  |                               |                            |
| AES-192/XTS       | **618 Mbps**  |                               |                            |
| AES-256/XTS       | **578 Mbps**  |                               |                            |
| AES-128/IGE       | **836 Mbps**  | 150 Mbps <br> `5.56x slow`    |                            |
| AES-192/IGE       | **762 Mbps**  | 131 Mbps <br> `5.8x slow`     |                            |
| AES-256/IGE       | **698 Mbps**  | 117 Mbps <br> `5.96x slow`    |                            |
| AES-128/PCBC      | **835 Mbps**  |                               |                            |
| AES-192/PCBC      | **774 Mbps**  |                               |                            |
| AES-256/PCBC      | **700 Mbps**  |                               |                            |

With 5KB message (5000 iterations):

| Algorithms        | `cipherlib`   | `PointyCastle`                | `cryptography`             |
| ----------------- | ------------- | ----------------------------- | -------------------------- |
| XOR               | **6.74 Gbps** |
| ChaCha20          | **1.26 Gbps** | 277 Mbps <br> `4.55x slow`    |                            |
| ChaCha20/Poly1305 | **765 Mbps**  | 198 Mbps <br> `3.87x slow`    | 280 Mbps <br> `2.73x slow` |
| Salsa20           | **1.25 Gbps** | 254 Mbps <br> `4.9x slow`     |                            |
| Salsa20/Poly1305  | **761 Mbps**  |                               |                            |
| AES-128/ECB       | **953 Mbps**  | 165 Mbps <br> `5.77x slow`    |                            |
| AES-192/ECB       | **866 Mbps**  | 144 Mbps <br> `6.01x slow`    |                            |
| AES-256/ECB       | **790 Mbps**  | 128 Mbps <br> `6.18x slow`    |                            |
| AES-128/CBC       | **973 Mbps**  | 158 Mbps <br> `6.15x slow`    | 854 Mbps <br> `1.14x slow` |
| AES-192/CBC       | **879 Mbps**  | 138 Mbps <br> `6.35x slow`    | 774 Mbps <br> `1.14x slow` |
| AES-256/CBC       | **798 Mbps**  | 123 Mbps <br> `6.49x slow`    | 708 Mbps <br> `1.13x slow` |
| AES-128/CTR       | **950 Mbps**  | 156 Mbps <br> `6.1x slow`     | 503 Mbps <br> `1.89x slow` |
| AES-192/CTR       | **866 Mbps**  | 138 Mbps <br> `6.3x slow`     | 475 Mbps <br> `1.82x slow` |
| AES-256/CTR       | **780 Mbps**  | 122 Mbps <br> `6.39x slow`    | 450 Mbps <br> `1.73x slow` |
| AES-128/GCM       | **145 Mbps**  | 11.72 Mbps <br> `12.34x slow` | 131 Mbps <br> `1.11x slow` |
| AES-192/GCM       | **144 Mbps**  | 11.7 Mbps <br> `12.3x slow`   | 128 Mbps <br> `1.12x slow` |
| AES-256/GCM       | **141 Mbps**  | 11.59 Mbps <br> `12.12x slow` | 128 Mbps <br> `1.1x slow`  |
| AES-128/CFB       | **453 Mbps**  | 136 Mbps <br> `3.32x slow`    |                            |
| AES-192/CFB       | **419 Mbps**  | 121 Mbps <br> `3.47x slow`    |                            |
| AES-256/CFB       | **381 Mbps**  | 108 Mbps <br> `3.54x slow`    |                            |
| AES-128/OFB       | **760 Mbps**  | 158 Mbps <br> `4.8x slow`     |                            |
| AES-192/OFB       | **747 Mbps**  | 139 Mbps <br> `5.39x slow`    |                            |
| AES-256/OFB       | **689 Mbps**  | 123 Mbps <br> `5.61x slow`    |                            |
| AES-128/XTS       | **688 Mbps**  |                               |                            |
| AES-192/XTS       | **634 Mbps**  |                               |                            |
| AES-256/XTS       | **595 Mbps**  |                               |                            |
| AES-128/IGE       | **843 Mbps**  | 151 Mbps <br> `5.59x slow`    |                            |
| AES-192/IGE       | **770 Mbps**  | 133 Mbps <br> `5.77x slow`    |                            |
| AES-256/IGE       | **710 Mbps**  | 119 Mbps <br> `5.96x slow`    |                            |
| AES-128/PCBC      | **843 Mbps**  |                               |                            |
| AES-192/PCBC      | **778 Mbps**  |                               |                            |
| AES-256/PCBC      | **690 Mbps**  |                               |                            |

With 16B message (100000 iterations):

| Algorithms        | `cipherlib`   | `PointyCastle`                | `cryptography`                   |
| ----------------- | ------------- | ----------------------------- | -------------------------------- |
| XOR               | **4.65 Gbps** |
| ChaCha20          | **420 Mbps**  | 50.69 Mbps <br> `8.29x slow`  |                                  |
| ChaCha20/Poly1305 | **110 Mbps**  | 41.08 Mbps <br> `2.68x slow`  | 34.87 Mbps <br> `3.15x slow`     |
| Salsa20           | **410 Mbps**  | 48.25 Mbps <br> `8.51x slow`  |                                  |
| Salsa20/Poly1305  | **110 Mbps**  |                               |                                  |
| AES-128/ECB       | **358 Mbps**  | 54.07 Mbps <br> `6.61x slow`  |                                  |
| AES-192/ECB       | **313 Mbps**  | 49.44 Mbps <br> `6.33x slow`  |                                  |
| AES-256/ECB       | **280 Mbps**  | 45.83 Mbps <br> `6.12x slow`  |                                  |
| AES-128/CBC       | **312 Mbps**  | 50.29 Mbps <br> `6.2x slow`   | 146 Mbps <br> `2.13x slow`       |
| AES-192/CBC       | **286 Mbps**  | 47.28 Mbps <br> `6.04x slow`  | 142 Mbps <br> `2.02x slow`       |
| AES-256/CBC       | **254 Mbps**  | 44.26 Mbps <br> `5.74x slow`  | 132 Mbps <br> `1.92x slow`       |
| AES-128/CTR       | **493 Mbps**  | 50.47 Mbps <br> `9.78x slow`  | 80.75 Mbps <br> `6.11x slow`     |
| AES-192/CTR       | **480 Mbps**  | 46.99 Mbps <br> `10.22x slow` | 78.85 Mbps <br> `6.09x slow`     |
| AES-256/CTR       | **425 Mbps**  | 43.79 Mbps <br> `9.7x slow`   | 76 Mbps <br> `5.59x slow`        |
| AES-128/GCM       | 27.19 Mbps    | 6.44 Mbps <br> `4.22x slow`   | **41.33 Mbps** <br> `1.52x fast` |
| AES-192/GCM       | 27.06 Mbps    | 6.38 Mbps <br> `4.24x slow`   | **40.41 Mbps** <br> `1.49x fast` |
| AES-256/GCM       | 26.68 Mbps    | 6.27 Mbps <br> `4.26x slow`   | **39.05 Mbps** <br> `1.46x fast` |
| AES-128/CFB       | **307 Mbps**  | 50.4 Mbps <br> `6.1x slow`    |                                  |
| AES-192/CFB       | **288 Mbps**  | 46.91 Mbps <br> `6.13x slow`  |                                  |
| AES-256/CFB       | **254 Mbps**  | 43.66 Mbps <br> `5.81x slow`  |                                  |
| AES-128/OFB       | **433 Mbps**  | 51.04 Mbps <br> `8.48x slow`  |                                  |
| AES-192/OFB       | **423 Mbps**  | 47.07 Mbps <br> `8.99x slow`  |                                  |
| AES-256/OFB       | **364 Mbps**  | 44.54 Mbps <br> `8.18x slow`  |                                  |
| AES-128/XTS       | **229 Mbps**  |                               |                                  |
| AES-192/XTS       | **224 Mbps**  |                               |                                  |
| AES-256/XTS       | **196 Mbps**  |                               |                                  |
| AES-128/IGE       | **275 Mbps**  | 49.15 Mbps <br> `5.6x slow`   |                                  |
| AES-192/IGE       | **270 Mbps**  | 45.42 Mbps <br> `5.94x slow`  |                                  |
| AES-256/IGE       | **238 Mbps**  | 42.69 Mbps <br> `5.58x slow`  |                                  |
| AES-128/PCBC      | **303 Mbps**  |                               |                                  |
| AES-192/PCBC      | **288 Mbps**  |                               |                                  |
| AES-256/PCBC      | **248 Mbps**  |                               |                                  |

> All benchmarks are done on _AMD Ryzen 7 5800X_ processor and _3200MHz_ RAM using compiled _exe_
>
> Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
