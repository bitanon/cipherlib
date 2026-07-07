// Copyright (c) 2026, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'algorithms/blowfish_modes/cbc.dart';
import 'algorithms/blowfish_modes/ctr.dart';
import 'algorithms/blowfish_modes/ecb.dart';
import 'algorithms/padding.dart';

export 'algorithms/blowfish_modes/cbc.dart';
export 'algorithms/blowfish_modes/ctr.dart';
export 'algorithms/blowfish_modes/ecb.dart';
export 'core/blowfish.dart';

/// Blowfish is a 64-bit symmetric-key block cipher designed by Bruce Schneier
/// in 1993. It accepts a variable-length key from 1 to 56 bytes, which is
/// expanded into 18 P-box entries and four key-dependent S-boxes using the
/// hexadecimal digits of PI.
///
/// It remains widely deployed in legacy protocols, although its 64-bit block
/// size makes it unsuitable for encrypting large volumes of data with a
/// single key. For new applications, consider [AES][aes] instead.
///
/// This implementation is based on the [Blowfish][spec] specification by
/// Bruce Schneier.
///
/// [spec]: https://www.schneier.com/academic/blowfish/
/// [aes]: https://doi.org/10.6028/NIST.FIPS.197-upd1
class Blowfish {
  /// The key for encryption and decryption
  final List<int> key;

  /// The padding scheme for the messages
  final Padding padding;

  /// Creates a Blowfish algorithm instance with the [key], where the length
  /// of the key must be between 1 and 56-bytes. An additional [padding]
  /// parameter can be configured for modes that requires a padding scheme.
  const Blowfish(
    this.key, [
    this.padding = Padding.pkcs7,
  ]);

  /// Creates Blowfish instances with [Padding.none]
  factory Blowfish.noPadding(List<int> key) => Blowfish(key, Padding.none);

  /// Creates Blowfish instances with [Padding.byte]
  factory Blowfish.byte(List<int> key) => Blowfish(key, Padding.byte);

  /// Creates Blowfish instances with [Padding.ansi]
  factory Blowfish.ansi(List<int> key) => Blowfish(key, Padding.ansi);

  /// Creates Blowfish instances with [Padding.pkcs7]
  factory Blowfish.pkcs7(List<int> key) => Blowfish(key, Padding.pkcs7);

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
  /// PT ---> [Blowfish] ---> CT
  /// ```
  ///
  /// [spec]: https://csrc.nist.gov/pubs/sp/800/38/a/final
  BlowfishInECBMode ecb() => BlowfishInECBMode(key, padding);

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
  /// - [iv] (initialization vector) is the random 8-byte salt.
  ///
  /// ```
  ///           IV          (Key)
  ///            |            |
  ///            v            v
  /// PT1 ---> (XOR) ---> [Blowfish] ---> CT1
  ///             _________________________|
  ///            |          (Key)
  ///            |            |
  ///            v            v
  /// PT2 ---> (XOR) ---> [Blowfish] ---> CT2
  /// ```
  ///
  /// [spec]: https://csrc.nist.gov/pubs/sp/800/38/a/final
  BlowfishInCBCMode cbc(List<int> iv) => BlowfishInCBCMode(
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
  /// - [iv] 64-bit salt (combination of nonce and counter)
  /// - [counterBits] Number of bits to use for the counter (1-64)
  ///
  /// ```
  /// (IV = Nonce + Counter)   (Key)
  ///            |               |
  ///            v               v
  ///        [Counter] ---> [Blowfish]
  ///                            |
  /// PT1 -------------------> (XOR) ---> CT1
  ///
  /// (IV = Nonce + Counter + 1)  (Key)
  ///            |                 |
  ///            v                 v
  ///        [Counter] ---> [Blowfish]
  ///                            |
  /// PT2 ---------------------> (XOR) ---> CT2
  /// ```
  ///
  /// [spec]: https://csrc.nist.gov/pubs/sp/800/38/a/final
  BlowfishInCTRMode ctr(List<int> iv, [int counterBits = 64]) =>
      BlowfishInCTRMode(key, iv, counterBits);
}
