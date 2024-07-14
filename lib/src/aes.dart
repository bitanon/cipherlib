// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/src/algorithms/aes/cbc.dart';
import 'package:cipherlib/src/algorithms/aes/cfb.dart';
import 'package:cipherlib/src/algorithms/aes/ctr.dart';
import 'package:cipherlib/src/algorithms/aes/ecb.dart';
import 'package:cipherlib/src/algorithms/aes/gcm.dart';
import 'package:cipherlib/src/algorithms/aes/ofb.dart';
import 'package:cipherlib/src/algorithms/aes/pcbc.dart';
import 'package:cipherlib/src/algorithms/aes/xts.dart';
import 'package:cipherlib/src/algorithms/padding.dart';

export 'package:cipherlib/src/algorithms/aes/cbc.dart';
export 'package:cipherlib/src/algorithms/aes/cfb.dart';
export 'package:cipherlib/src/algorithms/aes/ctr.dart';
export 'package:cipherlib/src/algorithms/aes/ecb.dart';
export 'package:cipherlib/src/algorithms/aes/gcm.dart';
export 'package:cipherlib/src/algorithms/aes/ofb.dart';
export 'package:cipherlib/src/algorithms/aes/pcbc.dart';
export 'package:cipherlib/src/algorithms/aes/xts.dart';

/// AES (Advanced Encryption Standard) is a symmetric encryption algorithm used
/// for securing data. It operates on fixed-size blocks of data (128 bits) using
/// keys of 128, 192, or 256 bits.
///
/// The process involves multiple rounds of substitution, permutation, mixing,
/// and key addition to transform plaintext into ciphertext. Decryption reverses
/// this process, using the same key to recover the original plaintext.
///
/// AES is known for its high speed and strong security, making it suitable for
/// various applications,including data protection in software and hardware.
class AES {
  /// The key for encryption and decryption
  final List<int> key;

  /// The padding scheme for the messages
  final Padding padding;

  /// Creates an AES algorithm instance with the [key], where the length of
  /// the key must be either 16, 24, or 32-bytes. An additional [padding]
  /// parameter can be configured for modes that requires a padding scheme.
  const AES(
    this.key, [
    this.padding = Padding.pkcs7,
  ]);

  /// Creates AES instances with [Padding.none]
  factory AES.noPadding(List<int> key) => AES(key, Padding.none);

  /// Creates AES instances with [Padding.byte]
  factory AES.byte(List<int> key) => AES(key, Padding.byte);

  /// Creates AES instances with [Padding.ansi]
  factory AES.ansi(List<int> key) => AES(key, Padding.ansi);

  /// Creates AES instances with [Padding.pkcs7]
  factory AES.pkcs7(List<int> key) => AES(key, Padding.pkcs7);

  /// The Electronic Codeblock (ECB) mode encrypts each block of plaintext
  /// independently using the same key.
  ///
  /// **Not Recommended: It is vulnerable to pattern analysis.**
  ///
  /// This implementation follows the specification from [NIST SP 800-38A -
  /// Recommendation for Block Cipher Modes of Operation: Methods and
  /// Techniques][spec].
  ///
  /// ```
  ///                     key
  ///                      |
  ///                      v
  /// Plaintext ---> [block cipher] ---> Ciphertext
  ///
  ///                     key
  ///                      |
  ///                      v
  /// Plaintext ---> [block cipher] ---> Ciphertext
  ///
  ///                     key
  ///                      |
  ///                      v
  /// Plaintext ---> [block cipher] ---> Ciphertext
  /// ```
  ///
  /// [spec]: https://csrc.nist.gov/pubs/sp/800/38/a/final
  AESInECBMode ecb() => AESInECBMode(key, padding);

  /// The Cipher Block Chaining (CBC) mode chains together blocks of plaintext
  /// by XORing each block with the previous ciphertext block before encryption.
  /// An initialization vector (IV) is used for the first block to ensure unique
  /// encryption. CBC mode provides better security than ECB but requires
  /// sequential processing.
  ///
  /// This implementation follows the specification from [NIST SP 800-38A -
  /// Recommendation for Block Cipher Modes of Operation: Methods and
  /// Techniques][spec].
  ///
  /// Parameters:
  /// - [iv] (initialization vector) is the random 16-byte salt.
  ///
  /// ```
  ///                 IV             Key
  ///                  |              |
  ///                  v              v
  /// Plaintext ---> (XOR) ---> [block cipher] ---> Ciphertext
  ///                   ________________________________|
  ///                  |             Key
  ///                  |              |
  ///                  v              v
  /// Plaintext ---> (XOR) ---> [block cipher] ---> Ciphertext
  ///                   ________________________________|
  ///                  |             Key
  ///                  |              |
  ///                  v              v
  /// Plaintext ---> (XOR) ---> [block cipher] ---> Ciphertext
  /// ```
  ///
  /// [spec]: https://csrc.nist.gov/pubs/sp/800/38/a/final
  AESInCBCMode cbc(List<int> iv) => AESInCBCMode(
        key,
        iv: iv,
        padding: padding,
      );

  /// The Counter (CTR) mode converts a block cipher into a stream cipher by
  /// encrypting a counter value with a nonce. The resulting keystream is then
  /// XORed with the plaintext to produce ciphertext. CTR mode allows parallel
  /// encryption and decryption, making it efficient for high-performance
  /// applications.
  ///
  /// This implementation follows the specification from [NIST SP 800-38A -
  /// Recommendation for Block Cipher Modes of Operation: Methods and
  /// Techniques][spec].
  ///
  /// Parameters:
  /// - [iv] (initialization vector) is the random 16-byte salt. For CTR mode
  ///   this is a combination of 64-bit Nonce and 64-bit Counter values in
  ///   Big-Endian order.
  ///
  /// ```
  ///                              Key          Plaintext
  ///                               |               |
  ///                               v               v
  /// <Nonce, Counter> -----> [block cipher] ---> (XOR) ---> Ciphertext
  ///
  ///                              Key          Plaintext
  ///                               |               |
  ///                               v               v
  /// <Nonce, Counter+1> ---> [block cipher] ---> (XOR) ---> Ciphertext
  ///
  ///                              Key          Plaintext
  ///                               |               |
  ///                               v               v
  /// <Nonce, Counter+1> ---> [block cipher] ---> (XOR) ---> Ciphertext
  /// ```
  ///
  /// [spec]: https://csrc.nist.gov/pubs/sp/800/38/a/final
  AESInCTRMode ctr(List<int> iv) => AESInCTRMode(key, iv);

  /// The CFB (Cipher Feedback) mode turns a block cipher into a
  /// self-synchronizing stream cipher. It uses the previous ciphertext block as
  /// input to the block cipher to produce a keystream, which is then XORed with
  /// the plaintext to produce ciphertext. CFB does not require a padding to the
  /// plaintext and can be used for error recovery.
  ///
  /// This implementation follows the specification from [NIST SP 800-38A -
  /// Recommendation for Block Cipher Modes of Operation: Methods and
  /// Techniques][spec].
  ///
  /// Parameters:
  /// - [iv] (initialization vector) is the random 16-byte salt.
  /// - [sbyte] number of bytes to take per block. (Default: 16)
  ///
  /// ```
  ///              Key                      Plaintext (s-bit)
  ///               |                            |
  ///               v                            v
  /// IV ---> [block cipher] -- [>>(16-s)] --> (XOR) ---> Ciphertext
  ///     |         _____________________________|        (s-bit)
  ///     |        |
  ///     v        v
  ///  [<< s] -> (XOR)     Key                    Plaintext (s-bit)
  ///      ________|        |                          |
  ///     |        |        v                          v
  ///     |        -> [block cipher] --[>>(16-s)]--> (XOR) --> (s-bit)
  ///     |         ___________________________________|
  ///     |        |
  ///     v        v
  ///  [<< s] -> (XOR)     Key                    Plaintext (s-bit)
  ///              |        |                          |
  ///              |        v                          v
  ///              -> [block cipher] --[>>(16-s)]--> (XOR) --> (s-bit)
  /// ```
  ///
  /// [spec]: https://csrc.nist.gov/pubs/sp/800/38/a/final
  AESInCFBMode cfb(
    List<int> iv, [
    int sbyte = 16,
  ]) =>
      AESInCFBMode(
        key,
        iv: iv,
        sbyte: sbyte,
      );

  /// Variant of [cfb] with s = 8
  AESInCFBMode cfb8(List<int> iv) => cfb(iv, 1);

  /// Variant of [cfb] with s = 64
  AESInCFBMode cfb64(List<int> iv) => cfb(iv, 8);

  /// Variant of [cfb] with s = 128
  AESInCFBMode cfb128(List<int> iv) => cfb(iv, 16);

  /// The Output Feedback (OFB) mode operates similarly to CFB but generates the
  /// keystream independently of both plaintext and ciphertext. This makes OFB
  /// immune to transmission errors but requires careful management of the IV to
  /// avoid security issues.
  ///
  /// This implementation follows the specification from [NIST SP 800-38A -
  /// Recommendation for Block Cipher Modes of Operation: Methods and
  /// Techniques][spec].
  ///
  /// Parameters:
  /// - [iv] (initialization vector) is the random 16-byte salt.
  ///
  /// ```
  ///              Key             Plaintext
  ///               |                  |
  ///               v                  v
  /// IV ---> [block cipher] ------> (XOR) ---> Ciphertext
  ///     _____________________|
  ///    |         Key             Plaintext
  ///    |          |                  |
  ///    |          v                  v
  ///    ---> [block cipher] ------> (XOR) ---> Ciphertext
  ///     _____________________|
  ///    |         Key             Plaintext
  ///    |          |                  |
  ///    |          v                  v
  ///    ---> [block cipher] ------> (XOR) ---> Ciphertext
  /// ```
  ///
  /// [spec]: https://csrc.nist.gov/pubs/sp/800/38/a/final
  AESInOFBMode ofb(
    List<int> iv, [
    int sbyte = 16,
  ]) =>
      AESInOFBMode(
        key,
        iv: iv,
        sbyte: sbyte,
      );

  /// Variant of [ofb] with s = 8
  AESInOFBMode ofb8(List<int> iv) => ofb(iv, 1);

  /// Variant of [ofb] with s = 64
  AESInOFBMode ofb64(List<int> iv) => ofb(iv, 8);

  /// Variant of [ofb] with s = 128
  AESInOFBMode ofb128(List<int> iv) => ofb(iv, 16);

  /// The Propagating Cipher Block Chaining (PCBC) mode is a variant of CBC that
  /// propagates changes to both the plaintext and the ciphertext, making it
  /// more resilient to certain attacks. It is not as commonly used as other
  /// modes but can provide additional security in some scenarios.
  ///
  /// Parameters:
  /// - [iv] (initialization vector) is the random 16-byte salt.
  ///
  /// ```
  ///                 IV             Key
  ///                  |              |
  ///                  v              v
  /// Plaintext ---> (XOR) ---> [block cipher] ---> Ciphertext
  ///            |      _________________________________|
  ///            |     |
  ///            --> (XOR)           Key
  ///                  |              |
  ///                  v              v
  /// Plaintext ---> (XOR) ---> [block cipher] ---> Ciphertext
  ///            |      _________________________________|
  ///            |     |
  ///            --> (XOR)           Key
  ///                  |              |
  ///                  v              v
  /// Plaintext ---> (XOR) ---> [block cipher] ---> Ciphertext
  /// ```
  AESInPCBCMode pcbc(List<int> iv) => AESInPCBCMode(
        key,
        iv: iv,
        padding: padding,
      );

  /// The Galois Counter Mode (GCM) is an advanced mode of operation for block
  /// ciphers that combines the counter mode of encryption with Galois field
  /// multiplication for authentication. GCM provides both data confidentiality
  /// and authenticity, making it a widely used and highly secure mode.
  ///
  /// This implementation follows the specification from [NIST SP 800-38D -
  /// Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode
  /// (GCM) and GMAC][spec].
  ///
  /// Parameters:
  /// - [iv] (initialization vector) is the random salt of arbitrary length.
  /// - [aad] (additional authentication data) is used to generated unique tag.
  /// - [tagSize] Length of the authentication tag in bytes. (Default: 16)
  ///
  /// The encryption output of this mode is combined with the ciphertext and
  /// 128-bit message authentication tag. During decryption, the authentication
  /// tag is checked with the generated tag. It will throw [StateError] on
  /// verification failure or on invalid ciphertext size.
  ///
  /// [spec]: https://csrc.nist.gov/pubs/sp/800/38/d/final
  AESInGCMMode gcm(
    List<int> iv, {
    Iterable<int>? aad,
    int tagSize = 16,
  }) =>
      AESInGCMMode(
        key,
        iv: iv,
        aad: aad,
        tagSize: tagSize,
      );

  /// The XTS or XEX (XOR-Encrypt-XOR) Tweakable Block Cipher with Ciphertext
  /// Stealing mode is a disk encryption mode of operation for cryptographic
  /// block ciphers. _It is designed specifically for encrypting data stored on
  /// block-oriented storage devices_.
  ///
  /// This mode combines the advantages of [ecb] and [cbc] while avoiding their
  /// weaknesses, making it well-suited for disk encryption.
  ///
  /// This implementation follows the specification from [1619-2018 - IEEE
  /// Standard for Cryptographic Protection of Data on Block-Oriented Storage
  /// Devices][spec].
  ///
  /// Parameters:
  /// - [tweak] The initial tweak value (16-bytes). If you want to use the
  ///   sector value please use [AESInXTSMode.fromSector].
  ///
  /// The [key] is divided in two equal parts for the XTS mode, and first part
  /// is used as the sector key, second part as the cipher key.
  ///
  /// [spec]: https://ieeexplore.ieee.org/document/8637988
  AESInXTSMode xts(List<int> tweak) => AESInXTSMode(key, tweak);
}
