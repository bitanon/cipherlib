## 0.3.0

- 🛡️ Strengthened input validation for **AES-CBC** by requiring IV length to be exactly 16 bytes.
- 🔒 Improved AEAD verification behavior in **XChaCha20Poly1305** and **XSalsa20Poly1305** by throwing `StateError` on authentication failure.
- ⚙️ Applied security hardening and reliability fixes across AES-GCM, ChaCha20/Salsa20 internals, cipher core helpers, and typed-data utilities.
- ✅ Expanded test coverage with additional security and validation tests, including AES-GCM and typed-data cases.
- 🧪 Added broader **ChaCha20** and **Salsa20** test vectors and scenarios.


## 0.2.0

- **AES** in ECB, CBC, CTR, CFB, OFB, GCM, XTS, IGE, and PCBC modes.
- **ChaCha20** and **XChaCha20** stream ciphers with **Poly1305** AEAD (`ChaCha20Poly1305`, `XChaCha20Poly1305`).
- **Salsa20** and **XSalsa20** stream ciphers with **Poly1305** AEAD (`Salsa20Poly1305`, `XSalsa20Poly1305`).
- **XOR** stream cipher helpers.
