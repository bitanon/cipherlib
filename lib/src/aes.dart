// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'package:cipherlib/src/algorithms/aes/cbc.dart';
import 'package:cipherlib/src/algorithms/aes/cfb.dart';
import 'package:cipherlib/src/algorithms/aes/ctr.dart';
import 'package:cipherlib/src/algorithms/aes/ecb.dart';
import 'package:cipherlib/src/algorithms/aes/ofb.dart';
import 'package:cipherlib/src/algorithms/aes/pcbc.dart';
import 'package:cipherlib/src/algorithms/padding.dart';

export 'package:cipherlib/src/algorithms/aes/cbc.dart';
export 'package:cipherlib/src/algorithms/aes/cfb.dart';
export 'package:cipherlib/src/algorithms/aes/ctr.dart';
export 'package:cipherlib/src/algorithms/aes/ecb.dart';
export 'package:cipherlib/src/algorithms/aes/ofb.dart';
export 'package:cipherlib/src/algorithms/aes/pcbc.dart';

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
  AESInECBMode ecb() => AESInECBMode(key, padding);

  /// The Cipher Block Chaining (CBC) mode chains together blocks of plaintext
  /// by XORing each block with the previous ciphertext block before encryption.
  /// An initialization vector (IV) is used for the first block to ensure unique
  /// encryption. CBC mode provides better security than ECB but requires
  /// sequential processing.
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
  AESInCTRMode ctr(List<int> iv) => AESInCTRMode(key, iv);

  /// The CFB (Cipher Feedback) mode turns a block cipher into a
  /// self-synchronizing stream cipher. It uses the previous ciphertext block as
  /// input to the block cipher to produce a keystream, which is then XORed with
  /// the plaintext to produce ciphertext. CFB does not require a padding to the
  /// plaintext and can be used for error recovery.
  ///
  /// Parameters:
  /// - [iv] (initialization vector) is the random 16-byte salt.
  ///
  /// ```
  ///              Key          Plaintext
  ///               |               |
  ///               v               v
  /// IV ---> [block cipher] ---> (XOR) ---> Ciphertext
  ///     ________________________________________|
  ///    |         Key          Plaintext
  ///    |          |               |
  ///    |          v               v
  ///    ---> [block cipher] ---> (XOR) ---> Ciphertext
  ///     ________________________________________|
  ///    |         Key          Plaintext
  ///    |          |               |
  ///    |          v               v
  ///    ---> [block cipher] ---> (XOR) ---> Ciphertext
  /// ```
  AESInCFBMode cfb(List<int> iv) => AESInCFBMode(key, iv);

  /// The Output Feedback (OFB) mode operates similarly to CFB but generates the
  /// keystream independently of both plaintext and ciphertext. This makes OFB
  /// immune to transmission errors but requires careful management of the IV to
  /// avoid security issues.
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
  AESInOFBMode ofb(List<int> iv) => AESInOFBMode(key, iv);

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
}
