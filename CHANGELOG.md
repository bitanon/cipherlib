# 0.1.0

- ![dart support](https://img.shields.io/badge/dart-%3e%3d%202.19.0-39f?logo=dart)
- Bump dependency: hashlib
- Refactor internal files
- Fixes a few security issues:
  - AEAD sink reset keeps stale message length state
  - AEAD does not re-apply AAD framing after sink reset
  - AES-CTR accepts IVs > 16 bytes but silently ignores extra bytes

## 0.0.14

- `AES` in ECB, CBC, CTR, CFB, OFB, GCM, XTS, IGE, PCBC modes.
- `XChaCha20`, `ChaCha20` cipher with `Poly1305` tag.
- `XSalsa20`, `Salsa20` cipher with `Poly1305` tag.
- `XOR` cipher.
