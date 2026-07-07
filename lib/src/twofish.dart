// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'algorithms/padding.dart';
import 'algorithms/twofish_modes/cbc.dart';
import 'algorithms/twofish_modes/ctr.dart';
import 'algorithms/twofish_modes/ecb.dart';

export 'algorithms/twofish_modes/cbc.dart';
export 'algorithms/twofish_modes/ctr.dart';
export 'algorithms/twofish_modes/ecb.dart';
export 'core/twofish.dart';

/// Twofish is a 128-bit symmetric-key block cipher designed by Bruce
/// Schneier, John Kelsey, Doug Whiting, David Wagner, Chris Hall, and Niels
/// Ferguson. It was one of the five finalists of the AES contest, and it
/// remains unbroken. It uses keys of 128, 192, or 256 bits with a Feistel
/// network structure, key-dependent S-boxes, and an MDS matrix.
///
/// This implementation is based on the [Twofish][spec] specification.
///
/// [spec]: https://www.schneier.com/academic/twofish/
class Twofish {
  /// The key for encryption and decryption
  final List<int> key;

  /// The padding scheme for the messages
  final Padding padding;

  /// Creates a Twofish algorithm instance with the [key], where the length of
  /// the key must be either 16, 24, or 32-bytes. An additional [padding]
  /// parameter can be configured for modes that requires a padding scheme.
  const Twofish(
    this.key, [
    this.padding = Padding.pkcs7,
  ]);

  /// Creates Twofish instances with [Padding.none]
  factory Twofish.noPadding(List<int> key) => Twofish(key, Padding.none);

  /// Creates Twofish instances with [Padding.byte]
  factory Twofish.byte(List<int> key) => Twofish(key, Padding.byte);

  /// Creates Twofish instances with [Padding.ansi]
  factory Twofish.ansi(List<int> key) => Twofish(key, Padding.ansi);

  /// Creates Twofish instances with [Padding.pkcs7]
  factory Twofish.pkcs7(List<int> key) => Twofish(key, Padding.pkcs7);

  /// The Electronic Codeblock (ECB) mode encrypts each block of plaintext
  /// independently using the same key.
  ///
  /// **Not Recommended: It is vulnerable to pattern analysis.**
  ///
  /// This implementation follows the specification from [(NIST SP 800-38A) -
  /// Recommendation for Block Cipher Modes of Operation: Methods and
  /// Techniques][spec].
  ///
  /// ```
  ///            (key)
  ///              |
  ///              v
  /// PT ---> [Twofish] ---> CT
  /// ```
  ///
  /// [spec]: https://csrc.nist.gov/pubs/sp/800/38/a/final
  TwofishInECBMode ecb() => TwofishInECBMode(key, padding);

  /// The Cipher Block Chaining (CBC) mode chains together blocks of plaintext
  /// by XORing each block with the previous ciphertext block before encryption.
  /// An initialization vector (IV) is used for the first block to ensure unique
  /// encryption. CBC mode provides better security than ECB but requires
  /// sequential processing.
  ///
  /// This implementation follows the specification from [(NIST SP 800-38A) -
  /// Recommendation for Block Cipher Modes of Operation: Methods and
  /// Techniques][spec].
  ///
  /// Parameters:
  /// - [iv] (initialization vector) is the random 16-byte salt.
  ///
  /// ```
  ///           IV          (Key)
  ///            |            |
  ///            v            v
  /// PT1 ---> (XOR) ---> [Twofish] ---> CT1
  ///             ________________________|
  ///            |          (Key)
  ///            |            |
  ///            v            v
  /// PT2 ---> (XOR) ---> [Twofish] ---> CT2
  /// ```
  ///
  /// [spec]: https://csrc.nist.gov/pubs/sp/800/38/a/final
  TwofishInCBCMode cbc(List<int> iv) => TwofishInCBCMode(
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
  /// This implementation follows the specification from [(NIST SP 800-38A) -
  /// Recommendation for Block Cipher Modes of Operation: Methods and
  /// Techniques][spec].
  ///
  /// Parameters:
  /// - [iv] 128-bit salt (combination of nonce and counter)
  /// - [counterBits] Number of bits to use for the counter (1-128)
  ///
  /// ```
  /// (IV = Nonce + Counter)   (Key)
  ///            |               |
  ///            v               v
  ///        [Counter] ---> [Twofish]
  ///                            |
  /// PT1 -------------------> (XOR) ---> CT1
  ///
  /// (IV = Nonce + Counter + 1)  (Key)
  ///            |                 |
  ///            v                 v
  ///        [Counter] ---> [Twofish]
  ///                            |
  /// PT2 ---------------------> (XOR) ---> CT2
  /// ```
  ///
  /// [spec]: https://csrc.nist.gov/pubs/sp/800/38/a/final
  TwofishInCTRMode ctr(List<int> iv, [int counterBits = 64]) =>
      TwofishInCTRMode(key, iv, counterBits);
}
