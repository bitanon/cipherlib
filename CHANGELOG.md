## 0.4.0

- 🌊 Restored and redesigned stream processing support by refactoring cipher architecture around `StreamCipher`, `AEADStreamCipher`, and `CipherPair`.
- 🔐 Refactored AES modes, ChaCha20, Salsa20, XOR, and AEAD implementations to align behavior across one-shot and stream APIs.
- 🛠️ Updated nonce and typed-data internals plus AES cache generation logic for better correctness and maintainability.
- ✅ Expanded and updated test coverage across AES modes, stream ciphers, AEAD flows, integration parity, and core cipher behaviors.

## 0.3.0

- Removed Stream support (It will be available again in later versions).
- 🛡️ Strengthened input validation for **AES-CBC** by requiring IV length to be exactly 16 bytes.
- 🔒 Improved AEAD verification behavior in **XChaCha20Poly1305** and **XSalsa20Poly1305** by throwing `StateError` on authentication failure.
- ⚙️ Applied security hardening and reliability fixes across AES-GCM, ChaCha20/Salsa20 internals, cipher core helpers, and typed-data utilities.
- ✅ Expanded test coverage with additional security and validation tests, including AES-GCM and typed-data cases.
- 🧪 Added broader **ChaCha20** and **Salsa20** test vectors and scenarios.

## 0.2.0

- ⚙️ Refactored AES (all modes), ChaCha20, Salsa20, and AEAD internals for improved clarity and maintainability.
- 🚀 Improved performance across core cipher paths and benchmark implementations.
- ✅ Expanded and reorganized test coverage across AES, stream ciphers, nonce/padding behavior, and cross-library integration tests.
- 📊 Revamped benchmarking infrastructure and documentation, including native/compiled benchmark support and updated benchmark reports.
- 🛠️ Updated CI/release workflows, refreshed docs/examples, and bumped `hashlib` dependency.

## 0.1.0

- **AES** in ECB, CBC, CTR, CFB, OFB, GCM, XTS, IGE, and PCBC modes.
- **ChaCha20** and **XChaCha20** stream ciphers with **Poly1305** AEAD (`ChaCha20Poly1305`, `XChaCha20Poly1305`).
- **Salsa20** and **XSalsa20** stream ciphers with **Poly1305** AEAD (`Salsa20Poly1305`, `XSalsa20Poly1305`).
- **XOR** stream cipher helpers.
