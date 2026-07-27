# 0.7.2

- 🐛 Fix **AES-GCM** producing wrong ciphertext on `dart2wasm` for messages of
  about 1 MiB or larger
  ([#28](https://github.com/bitanon/cipherlib/issues/28)). The block counter is
  stored in a `Uint8List`
  view over another buffer, and dart2wasm skips the modulo-256 truncation when
  such a view is assigned an out-of-range value, so `counter[i]++` let the carry
  bleed into the neighbouring byte. From the first 32-bit carry onward the
  keystream desynchronised, silently breaking interoperability with every other
  platform (and with other AES-GCM implementations). All stored counter bytes
  are now masked explicitly.
- ✅ The `inc32` counter behaviour is now pinned against raw AES-ECB at every
  byte-carry boundary, plus an end-to-end check across the 1 MiB boundary, and
  the `dart2wasm` suite runs on every push instead of only at release time.
- ✅ New cross-cutting `test/counter_boundary_test.dart` asserts counter
  continuity — block `j` of a run started at counter `C` equals block `0` of a
  run started at `C + j` — for AES/Twofish/Blowfish CTR, ChaCha20 (32- and
  64-bit counters), XChaCha20, Salsa20 and XSalsa20. Because the starting
  counter is an input, this reaches the 32- and 64-bit carries that no
  achievable message length could walk to, alongside a 1 MiB run per cipher.
- Improve the benchmark harness (`benchmark/_base.dart`): it now reports the
  median per-iteration time sampled across ~25ms batches instead of the
  arithmetic mean, making results robust against GC pauses and keeping each
  batch well above the coarsened web timer resolution. Benchmark tooling only;
  no library code or output is affected.

# 0.7.1

- Bump `hashlib` to `^2.4.2`.

# 0.7.0

- 🔑 Added **ML-KEM** (NIST FIPS 203) post-quantum cryptography with `MLKEM.kem512()`, `MLKEM.kem768()`, and `MLKEM.kem1024()`, supporting key generation, encapsulation, and decapsulation, with deterministic key generation from a 64-byte seed.
- 🧩 Added `KEMBase`, `KEMKeyPair`, and `KEMSecret` core types for key encapsulation mechanisms.

# 0.6.0

- 🐡 Added **Blowfish** block cipher with `ECB`, `CBC`, and `CTR` modes, supporting variable key sizes from 1 to 56 bytes.
- 🐟 Added **Twofish** block cipher with `ECB`, `CBC`, and `CTR` modes, supporting 128, 192, and 256-bit keys.

# 0.5.0

- 🔐 Added **AES-CCM** (Counter with CBC-MAC, RFC-3610) support with `AES(key).ccm(nonce)`, accepting a 7 to 13 byte nonce, additional authenticated data, and a configurable tag size.
- 🔤 Renamed AEAD extensions to fix a spelling error: `ChaCha20ExtentionForPoly1305`, `XChaCha20ExtentionForPoly1305`, `Salsa20ExtentionForPoly1305`, and `XSalsa20ExtentionForPoly1305` are now `...ExtensionForPoly1305` (breaking change).
- 📝 Corrected the README features table by removing unavailable `*Stream` helper functions, and refreshed the embedded usage example.

# 0.4.0

- 🌊 Restored and redesigned stream processing support by refactoring cipher architecture around `StreamCipher`, `AEADStreamCipher`, and `CipherPair`.
- 🔐 Refactored AES modes, ChaCha20, Salsa20, XOR, and AEAD implementations to align behavior across one-shot and stream APIs.
- 🛠️ Updated nonce and typed-data internals plus AES cache generation logic for better correctness and maintainability.
- ✅ Expanded and updated test coverage across AES modes, stream ciphers, AEAD flows, integration parity, and core cipher behaviors.

# 0.3.0

- Removed Stream support (It will be available again in later versions).
- 🛡️ Strengthened input validation for **AES-CBC** by requiring IV length to be exactly 16 bytes.
- 🔒 Improved AEAD verification behavior in **XChaCha20Poly1305** and **XSalsa20Poly1305** by throwing `StateError` on authentication failure.
- ⚙️ Applied security hardening and reliability fixes across AES-GCM, ChaCha20/Salsa20 internals, cipher core helpers, and typed-data utilities.
- ✅ Expanded test coverage with additional security and validation tests, including AES-GCM and typed-data cases.
- 🧪 Added broader **ChaCha20** and **Salsa20** test vectors and scenarios.

# 0.2.0

- ⚙️ Refactored AES (all modes), ChaCha20, Salsa20, and AEAD internals for improved clarity and maintainability.
- 🚀 Improved performance across core cipher paths and benchmark implementations.
- ✅ Expanded and reorganized test coverage across AES, stream ciphers, nonce/padding behavior, and cross-library integration tests.
- 📊 Revamped benchmarking infrastructure and documentation, including native/compiled benchmark support and updated benchmark reports.
- 🛠️ Updated CI/release workflows, refreshed docs/examples, and bumped `hashlib` dependency.

# 0.1.0

- **AES** in ECB, CBC, CTR, CFB, OFB, GCM, XTS, IGE, and PCBC modes.
- **ChaCha20** and **XChaCha20** stream ciphers with **Poly1305** AEAD (`ChaCha20Poly1305`, `XChaCha20Poly1305`).
- **Salsa20** and **XSalsa20** stream ciphers with **Poly1305** AEAD (`Salsa20Poly1305`, `XSalsa20Poly1305`).
- **XOR** stream cipher helpers.
