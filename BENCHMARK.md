# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib
- **PointyCastle** : https://pub.dev/packages/pointycastle
- **Cryptography** : https://pub.dev/packages/cryptography

With 1MB message:

| Algorithms         | `cipherlib`   | `PointyCastle`                | `cryptography`              |
| ------------------ | ------------- | ----------------------------- | --------------------------- |
| XOR                | **9.02 Gbps** |                               |                             |
| Salsa20            | **2.14 Gbps** | 352 Mbps <br> `6.08x slow`    |                             |
| Salsa20/Poly1305   | **2.11 Gbps** |                               |                             |
| XSalsa20           | **2.14 Gbps** |                               |                             |
| XSalsa20/Poly1305  | **2.14 Gbps** |                               |                             |
| ChaCha20           | **2.01 Gbps** | 355 Mbps <br> `5.65x slow`    |                             |
| ChaCha20/Poly1305  | **1.34 Gbps** | 275 Mbps <br> `4.88x slow`    | 282 Mbps <br> `4.75x slow`  |
| XChaCha20          | **2 Gbps**    |                               |                             |
| XChaCha20/Poly1305 | **1.35 Gbps** |                               |                             |
| AES-128/CBC        | **1.47 Gbps** | 232 Mbps <br> `6.36x slow`    | 1.41 Gbps <br> `1.04x slow` |
| AES-192/CBC        | **1.27 Gbps** | 201 Mbps <br> `6.32x slow`    | 1.21 Gbps <br> `1.05x slow` |
| AES-256/CBC        | **1.11 Gbps** | 177 Mbps <br> `6.29x slow`    | 919 Mbps <br> `1.21x slow`  |
| AES-128/CCM        | **554 Mbps**  | 113 Mbps <br> `4.89x slow`    |                             |
| AES-192/CCM        | **497 Mbps**  | 98.45 Mbps <br> `5.05x slow`  |                             |
| AES-256/CCM        | **450 Mbps**  | 87.59 Mbps <br> `5.13x slow`  |                             |
| AES-128/CFB        | **646 Mbps**  | 3.81 Mbps <br> `169.5x slow`  |                             |
| AES-192/CFB        | **567 Mbps**  | 3.83 Mbps <br> `148.07x slow` |                             |
| AES-256/CFB        | **506 Mbps**  | 3.85 Mbps <br> `131.59x slow` |                             |
| AES-128/CTR        | **1.54 Gbps** | 218 Mbps <br> `7.05x slow`    | 743 Mbps <br> `2.07x slow`  |
| AES-192/CTR        | **1.32 Gbps** | 191 Mbps <br> `6.9x slow`     | 689 Mbps <br> `1.92x slow`  |
| AES-256/CTR        | **1.16 Gbps** | 170 Mbps <br> `6.83x slow`    | 639 Mbps <br> `1.81x slow`  |
| AES-128/ECB        | **1.5 Gbps**  | 249 Mbps <br> `6.01x slow`    |                             |
| AES-192/ECB        | **1.29 Gbps** | 214 Mbps <br> `6.03x slow`    |                             |
| AES-256/ECB        | **1.13 Gbps** | 188 Mbps <br> `6x slow`       |                             |
| AES-128/GCM        | **231 Mbps**  | 12.52 Mbps <br> `18.45x slow` | 152 Mbps <br> `1.52x slow`  |
| AES-192/GCM        | **227 Mbps**  | 12.43 Mbps <br> `18.24x slow` | 154 Mbps <br> `1.47x slow`  |
| AES-256/GCM        | **222 Mbps**  | 12.3 Mbps <br> `18.07x slow`  | 144 Mbps <br> `1.54x slow`  |
| AES-128/IGE        | **1.42 Gbps** | 208 Mbps <br> `6.82x slow`    |                             |
| AES-192/IGE        | **1.24 Gbps** | 183 Mbps <br> `6.74x slow`    |                             |
| AES-256/IGE        | **1.09 Gbps** | 164 Mbps <br> `6.61x slow`    |                             |
| AES-128/OFB        | **636 Mbps**  | 120 Mbps <br> `5.28x slow`    |                             |
| AES-192/OFB        | **564 Mbps**  | 104 Mbps <br> `5.41x slow`    |                             |
| AES-256/OFB        | **502 Mbps**  | 91.54 Mbps <br> `5.48x slow`  |                             |
| AES-128/PCBC       | **1.46 Gbps** |                               |                             |
| AES-192/PCBC       | **1.27 Gbps** |                               |                             |
| AES-256/PCBC       | **1.11 Gbps** |                               |                             |
| AES-128/XTS        | **1.42 Gbps** |                               |                             |
| AES-192/XTS        | **1.23 Gbps** |                               |                             |
| AES-256/XTS        | **1.08 Gbps** |                               |                             |
| Blowfish-128/CBC   | **690 Mbps**  | 4.16 Mbps <br> `165.77x slow` |                             |
| Blowfish-256/CBC   | **693 Mbps**  | 3.99 Mbps <br> `173.58x slow` |                             |
| Blowfish-448/CBC   | **701 Mbps**  | 4.05 Mbps <br> `173.19x slow` |                             |
| Twofish-128/CBC    | **1.05 Gbps** | 4.15 Mbps <br> `251.76x slow` |                             |
| Twofish-192/CBC    | **1.04 Gbps** | 4.13 Mbps <br> `252.26x slow` |                             |
| Twofish-256/CBC    | **1.04 Gbps** | 3.82 Mbps <br> `272.64x slow` |                             |

With 1KB message:

| Algorithms         | `cipherlib`    | `PointyCastle`                | `cryptography`              |
| ------------------ | -------------- | ----------------------------- | --------------------------- |
| XOR                | **9.13 Gbps**  |                               |                             |
| Salsa20            | **2.04 Gbps**  | 334 Mbps <br> `6.12x slow`    |                             |
| Salsa20/Poly1305   | **1.97 Gbps**  |                               |                             |
| XSalsa20           | **2 Gbps**     |                               |                             |
| XSalsa20/Poly1305  | **1.86 Gbps**  |                               |                             |
| ChaCha20           | **1.98 Gbps**  | 349 Mbps <br> `5.68x slow`    |                             |
| ChaCha20/Poly1305  | **1.29 Gbps**  | 258 Mbps <br> `5x slow`       | 256 Mbps <br> `5.05x slow`  |
| XChaCha20          | **1.88 Gbps**  |                               |                             |
| XChaCha20/Poly1305 | **1.25 Gbps**  |                               |                             |
| AES-128/CBC        | **1.33 Gbps**  | 205 Mbps <br> `6.48x slow`    | 1.02 Gbps <br> `1.31x slow` |
| AES-192/CBC        | **1.17 Gbps**  | 177 Mbps <br> `6.6x slow`     | 867 Mbps <br> `1.35x slow`  |
| AES-256/CBC        | **1.02 Gbps**  | 159 Mbps <br> `6.41x slow`    | 785 Mbps <br> `1.3x slow`   |
| AES-128/CCM        | **525 Mbps**   | 97.57 Mbps <br> `5.38x slow`  |                             |
| AES-192/CCM        | **472 Mbps**   | 85.8 Mbps <br> `5.5x slow`    |                             |
| AES-256/CCM        | **416 Mbps**   | 76.68 Mbps <br> `5.43x slow`  |                             |
| AES-128/CFB        | **633 Mbps**   | 109 Mbps <br> `5.82x slow`    |                             |
| AES-192/CFB        | **558 Mbps**   | 94.26 Mbps <br> `5.92x slow`  |                             |
| AES-256/CFB        | **494 Mbps**   | 83.9 Mbps <br> `5.89x slow`   |                             |
| AES-128/CTR        | **1.48 Gbps**  | 198 Mbps <br> `7.45x slow`    | 588 Mbps <br> `2.51x slow`  |
| AES-192/CTR        | **1.27 Gbps**  | 173 Mbps <br> `7.38x slow`    | 553 Mbps <br> `2.3x slow`   |
| AES-256/CTR        | **1.11 Gbps**  | 151 Mbps <br> `7.37x slow`    | 511 Mbps <br> `2.17x slow`  |
| AES-128/ECB        | **1.33 Gbps**  | 219 Mbps <br> `6.09x slow`    |                             |
| AES-192/ECB        | **1.18 Gbps**  | 189 Mbps <br> `6.22x slow`    |                             |
| AES-256/ECB        | **1.03 Gbps**  | 167 Mbps <br> `6.17x slow`    |                             |
| AES-128/GCM        | **357 Mbps**   | 14.93 Mbps <br> `23.94x slow` | 246 Mbps <br> `1.45x slow`  |
| AES-192/GCM        | **346 Mbps**   | 14.33 Mbps <br> `24.11x slow` | 241 Mbps <br> `1.44x slow`  |
| AES-256/GCM        | **332 Mbps**   | 14.38 Mbps <br> `23.11x slow` | 223 Mbps <br> `1.49x slow`  |
| AES-128/IGE        | **1.3 Gbps**   | 187 Mbps <br> `6.98x slow`    |                             |
| AES-192/IGE        | **1.14 Gbps**  | 163 Mbps <br> `7.02x slow`    |                             |
| AES-256/IGE        | **999 Mbps**   | 148 Mbps <br> `6.77x slow`    |                             |
| AES-128/OFB        | **630 Mbps**   | 114 Mbps <br> `5.51x slow`    |                             |
| AES-192/OFB        | **558 Mbps**   | 97.34 Mbps <br> `5.73x slow`  |                             |
| AES-256/OFB        | **493 Mbps**   | 87.66 Mbps <br> `5.63x slow`  |                             |
| AES-128/PCBC       | **1.35 Gbps**  |                               |                             |
| AES-192/PCBC       | **1.17 Gbps**  |                               |                             |
| AES-256/PCBC       | **1.03 Gbps**  |                               |                             |
| AES-128/XTS        | **1.29 Gbps**  |                               |                             |
| AES-192/XTS        | **1.13 Gbps**  |                               |                             |
| AES-256/XTS        | **976 Mbps**   |                               |                             |
| Blowfish-128/CBC   | **78.33 Mbps** | 63.83 Mbps <br> `1.23x slow`  |                             |
| Blowfish-256/CBC   | **78.5 Mbps**  | 63.43 Mbps <br> `1.24x slow`  |                             |
| Blowfish-448/CBC   | **78.4 Mbps**  | 63.49 Mbps <br> `1.23x slow`  |                             |
| Twofish-128/CBC    | **630 Mbps**   | 320 Mbps <br> `1.97x slow`    |                             |
| Twofish-192/CBC    | **560 Mbps**   | 307 Mbps <br> `1.83x slow`    |                             |
| Twofish-256/CBC    | **493 Mbps**   | 289 Mbps <br> `1.7x slow`     |                             |

With 32B message:

| Algorithms         | `cipherlib`    | `PointyCastle`                | `cryptography`               |
| ------------------ | -------------- | ----------------------------- | ---------------------------- |
| XOR                | **8.11 Gbps**  |                               |                              |
| Salsa20            | **905 Mbps**   | 133 Mbps <br> `6.83x slow`    |                              |
| Salsa20/Poly1305   | **513 Mbps**   |                               |                              |
| XSalsa20           | **514 Mbps**   |                               |                              |
| XSalsa20/Poly1305  | **342 Mbps**   |                               |                              |
| ChaCha20           | **735 Mbps**   | 131 Mbps <br> `5.59x slow`    |                              |
| ChaCha20/Poly1305  | **303 Mbps**   | 115 Mbps <br> `2.62x slow`    | 65.19 Mbps <br> `4.64x slow` |
| XChaCha20          | **498 Mbps**   |                               |                              |
| XChaCha20/Poly1305 | **236 Mbps**   |                               |                              |
| AES-128/CBC        | **330 Mbps**   | 43.87 Mbps <br> `7.52x slow`  | 104 Mbps <br> `3.17x slow`   |
| AES-192/CBC        | **311 Mbps**   | 38.84 Mbps <br> `8.02x slow`  | 94.52 Mbps <br> `3.29x slow` |
| AES-256/CBC        | **270 Mbps**   | 37.07 Mbps <br> `7.3x slow`   | 86.91 Mbps <br> `3.11x slow` |
| AES-128/CCM        | **202 Mbps**   | 20.04 Mbps <br> `10.07x slow` |                              |
| AES-192/CCM        | **186 Mbps**   | 16.74 Mbps <br> `11.08x slow` |                              |
| AES-256/CCM        | **167 Mbps**   | 16.13 Mbps <br> `10.36x slow` |                              |
| AES-128/CFB        | **424 Mbps**   | 42.2 Mbps <br> `10.04x slow`  |                              |
| AES-192/CFB        | **392 Mbps**   | 37.01 Mbps <br> `10.6x slow`  |                              |
| AES-256/CFB        | **335 Mbps**   | 34.48 Mbps <br> `9.7x slow`   |                              |
| AES-128/CTR        | **611 Mbps**   | 48.98 Mbps <br> `12.46x slow` | 80.89 Mbps <br> `7.55x slow` |
| AES-192/CTR        | **582 Mbps**   | 43.59 Mbps <br> `13.35x slow` | 78.48 Mbps <br> `7.41x slow` |
| AES-256/CTR        | **496 Mbps**   | 40.81 Mbps <br> `12.16x slow` | 75.68 Mbps <br> `6.56x slow` |
| AES-128/ECB        | **353 Mbps**   | 47.36 Mbps <br> `7.46x slow`  |                              |
| AES-192/ECB        | **321 Mbps**   | 41.27 Mbps <br> `7.77x slow`  |                              |
| AES-256/ECB        | **279 Mbps**   | 38.47 Mbps <br> `7.25x slow`  |                              |
| AES-128/GCM        | **62.72 Mbps** | 4.95 Mbps <br> `12.67x slow`  | 50.09 Mbps <br> `1.25x slow` |
| AES-192/GCM        | **62.59 Mbps** | 4.93 Mbps <br> `12.7x slow`   | 48.74 Mbps <br> `1.28x slow` |
| AES-256/GCM        | **59.89 Mbps** | 4.87 Mbps <br> `12.3x slow`   | 45.61 Mbps <br> `1.31x slow` |
| AES-128/IGE        | **364 Mbps**   | 43.58 Mbps <br> `8.35x slow`  |                              |
| AES-192/IGE        | **329 Mbps**   | 38.19 Mbps <br> `8.61x slow`  |                              |
| AES-256/IGE        | **285 Mbps**   | 35.97 Mbps <br> `7.92x slow`  |                              |
| AES-128/OFB        | **431 Mbps**   | 42.55 Mbps <br> `10.12x slow` |                              |
| AES-192/OFB        | **398 Mbps**   | 37.31 Mbps <br> `10.66x slow` |                              |
| AES-256/OFB        | **340 Mbps**   | 34.65 Mbps <br> `9.81x slow`  |                              |
| AES-128/PCBC       | **381 Mbps**   |                               |                              |
| AES-192/PCBC       | **347 Mbps**   |                               |                              |
| AES-256/PCBC       | **296 Mbps**   |                               |                              |
| AES-128/XTS        | **328 Mbps**   |                               |                              |
| AES-192/XTS        | **308 Mbps**   |                               |                              |
| AES-256/XTS        | **252 Mbps**   |                               |                              |
| Blowfish-128/CBC   | **2.74 Mbps**  | 2.37 Mbps <br> `1.15x slow`   |                              |
| Blowfish-256/CBC   | **2.75 Mbps**  | 2.36 Mbps <br> `1.17x slow`   |                              |
| Blowfish-448/CBC   | **2.75 Mbps**  | 2.37 Mbps <br> `1.16x slow`   |                              |
| Twofish-128/CBC    | **45.46 Mbps** | 40.32 Mbps <br> `1.13x slow`  |                              |
| Twofish-192/CBC    | **36.02 Mbps** | 33.43 Mbps <br> `1.08x slow`  |                              |
| Twofish-256/CBC    | **28.26 Mbps** | 28.14 Mbps <br> `1x slow`     |                              |

> All benchmarks are done on 36GB _Apple M3 Pro_ using compiled _exe_
>
> Dart SDK version: 3.12.2 (stable) (Tue Jun 9 01:11:39 2026 -0700) on "macos_arm64"
