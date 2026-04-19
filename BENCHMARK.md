# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib
- **PointyCastle** : https://pub.dev/packages/pointycastle
- **Cryptography** : https://pub.dev/packages/cryptography

With 1MB message (10 iterations):

| Algorithms        | `cipherlib`   | `PointyCastle`                | `cryptography`                  |
| ----------------- | ------------- | ----------------------------- | ------------------------------- |
| XOR               | **7.43 Gbps** |                               |                                 |
| ChaCha20          | **1.87 Gbps** | 304 Mbps <br> `6.14x slow`    |                                 |
| ChaCha20/Poly1305 | **1.16 Gbps** | 233 Mbps <br> `4.97x slow`    | 235 Mbps <br> `4.92x slow`      |
| Salsa20           | **2.03 Gbps** | 304 Mbps <br> `6.67x slow`    |                                 |
| Salsa20/Poly1305  | **1.93 Gbps** |                               |                                 |
| AES-128/ECB       | **1.2 Gbps**  | 220 Mbps <br> `5.47x slow`    |                                 |
| AES-192/ECB       | **1.06 Gbps** | 194 Mbps <br> `5.44x slow`    |                                 |
| AES-256/ECB       | **957 Mbps**  | 172 Mbps <br> `5.56x slow`    |                                 |
| AES-128/CBC       | 1.2 Gbps      | 205 Mbps <br> `5.83x slow`    | **1.24 Gbps** <br> `1.03x fast` |
| AES-192/CBC       | 1.05 Gbps     | 182 Mbps <br> `5.78x slow`    | **1.08 Gbps** <br> `1.03x fast` |
| AES-256/CBC       | 956 Mbps      | 162 Mbps <br> `5.89x slow`    | **961 Mbps** <br> `1.01x fast`  |
| AES-128/CTR       | **1.13 Gbps** | 202 Mbps <br> `5.58x slow`    | 590 Mbps <br> `1.91x slow`      |
| AES-192/CTR       | **997 Mbps**  | 179 Mbps <br> `5.58x slow`    | 556 Mbps <br> `1.8x slow`       |
| AES-256/CTR       | **909 Mbps**  | 160 Mbps <br> `5.66x slow`    | 517 Mbps <br> `1.76x slow`      |
| AES-128/GCM       | **163 Mbps**  | 12.7 Mbps <br> `12.86x slow`  | 161 Mbps <br> `1.02x slow`      |
| AES-192/GCM       | 161 Mbps      | 12.61 Mbps <br> `12.78x slow` | **163 Mbps** <br> `1.01x fast`  |
| AES-256/GCM       | **158 Mbps**  | 12.51 Mbps <br> `12.67x slow` | 154 Mbps <br> `1.03x slow`      |
| AES-128/CFB       | **579 Mbps**  | 3.23 Mbps <br> `179.18x slow` |                                 |
| AES-192/CFB       | **511 Mbps**  | 3.2 Mbps <br> `159.85x slow`  |                                 |
| AES-256/CFB       | **465 Mbps**  | 3.21 Mbps <br> `145.15x slow` |                                 |
| AES-128/OFB       | **1.08 Gbps** | 213 Mbps <br> `5.07x slow`    |                                 |
| AES-192/OFB       | **958 Mbps**  | 186 Mbps <br> `5.14x slow`    |                                 |
| AES-256/OFB       | **877 Mbps**  | 167 Mbps <br> `5.25x slow`    |                                 |
| AES-128/XTS       | **826 Mbps**  |                               |                                 |
| AES-192/XTS       | **758 Mbps**  |                               |                                 |
| AES-256/XTS       | **698 Mbps**  |                               |                                 |
| AES-128/IGE       | **1.05 Gbps** | 196 Mbps <br> `5.35x slow`    |                                 |
| AES-192/IGE       | **945 Mbps**  | 174 Mbps <br> `5.43x slow`    |                                 |
| AES-256/IGE       | **861 Mbps**  | 157 Mbps <br> `5.48x slow`    |                                 |
| AES-128/PCBC      | **1.05 Gbps** |                               |                                 |
| AES-192/PCBC      | **955 Mbps**  |                               |                                 |
| AES-256/PCBC      | **866 Mbps**  |                               |                                 |

With 5KB message (5000 iterations):

| Algorithms        | `cipherlib`   | `PointyCastle`                | `cryptography`                  |
| ----------------- | ------------- | ----------------------------- | ------------------------------- |
| XOR               | **9.1 Gbps**  |                               |                                 |
| ChaCha20          | **1.9 Gbps**  | 323 Mbps <br> `5.87x slow`    |                                 |
| ChaCha20/Poly1305 | **1.16 Gbps** | 254 Mbps <br> `4.55x slow`    | 257 Mbps <br> `4.51x slow`      |
| Salsa20           | **2.04 Gbps** | 317 Mbps <br> `6.46x slow`    |                                 |
| Salsa20/Poly1305  | **2.02 Gbps** |                               |                                 |
| AES-128/ECB       | **1.18 Gbps** | 235 Mbps <br> `5.05x slow`    |                                 |
| AES-192/ECB       | **1.05 Gbps** | 202 Mbps <br> `5.2x slow`     |                                 |
| AES-256/ECB       | **955 Mbps**  | 179 Mbps <br> `5.32x slow`    |                                 |
| AES-128/CBC       | 1.19 Gbps     | 218 Mbps <br> `5.45x slow`    | **1.23 Gbps** <br> `1.03x fast` |
| AES-192/CBC       | 1.04 Gbps     | 191 Mbps <br> `5.46x slow`    | **1.08 Gbps** <br> `1.03x fast` |
| AES-256/CBC       | 949 Mbps      | 170 Mbps <br> `5.57x slow`    | **959 Mbps** <br> `1.01x fast`  |
| AES-128/CTR       | **1.15 Gbps** | 212 Mbps <br> `5.42x slow`    | 599 Mbps <br> `1.92x slow`      |
| AES-192/CTR       | **1.01 Gbps** | 186 Mbps <br> `5.42x slow`    | 562 Mbps <br> `1.8x slow`       |
| AES-256/CTR       | **907 Mbps**  | 167 Mbps <br> `5.44x slow`    | 525 Mbps <br> `1.73x slow`      |
| AES-128/GCM       | **256 Mbps**  | 13.23 Mbps <br> `19.38x slow` | 218 Mbps <br> `1.17x slow`      |
| AES-192/GCM       | **244 Mbps**  | 13.11 Mbps <br> `18.58x slow` | 237 Mbps <br> `1.03x slow`      |
| AES-256/GCM       | **223 Mbps**  | 12.93 Mbps <br> `17.26x slow` | 205 Mbps <br> `1.09x slow`      |
| AES-128/CFB       | **580 Mbps**  | 188 Mbps <br> `3.09x slow`    |                                 |
| AES-192/CFB       | **508 Mbps**  | 153 Mbps <br> `3.32x slow`    |                                 |
| AES-256/CFB       | **464 Mbps**  | 143 Mbps <br> `3.26x slow`    |                                 |
| AES-128/OFB       | **1.07 Gbps** | 225 Mbps <br> `4.76x slow`    |                                 |
| AES-192/OFB       | **954 Mbps**  | 186 Mbps <br> `5.13x slow`    |                                 |
| AES-256/OFB       | **871 Mbps**  | 174 Mbps <br> `5x slow`       |                                 |
| AES-128/XTS       | **821 Mbps**  |                               |                                 |
| AES-192/XTS       | **754 Mbps**  |                               |                                 |
| AES-256/XTS       | **699 Mbps**  |                               |                                 |
| AES-128/IGE       | **1.05 Gbps** | 206 Mbps <br> `5.08x slow`    |                                 |
| AES-192/IGE       | **941 Mbps**  | 182 Mbps <br> `5.18x slow`    |                                 |
| AES-256/IGE       | **855 Mbps**  | 163 Mbps <br> `5.26x slow`    |                                 |
| AES-128/PCBC      | **1.05 Gbps** |                               |                                 |
| AES-192/PCBC      | **945 Mbps**  |                               |                                 |
| AES-256/PCBC      | **860 Mbps**  |                               |                                 |

With 16B message (100000 iterations):

| Algorithms        | `cipherlib`   | `PointyCastle`               | `cryptography`                   |
| ----------------- | ------------- | ---------------------------- | -------------------------------- |
| XOR               | **6.94 Gbps** |                              |                                  |
| ChaCha20          | **499 Mbps**  | 66.86 Mbps <br> `7.47x slow` |                                  |
| ChaCha20/Poly1305 | **197 Mbps**  | 59.09 Mbps <br> `3.33x slow` | 39.34 Mbps <br> `5x slow`        |
| Salsa20           | **534 Mbps**  | 66.7 Mbps <br> `8.01x slow`  |                                  |
| Salsa20/Poly1305  | **278 Mbps**  |                              |                                  |
| AES-128/ECB       | **426 Mbps**  | 70.57 Mbps <br> `6.03x slow` |                                  |
| AES-192/ECB       | **392 Mbps**  | 62.61 Mbps <br> `6.27x slow` |                                  |
| AES-256/ECB       | **341 Mbps**  | 59.21 Mbps <br> `5.76x slow` |                                  |
| AES-128/CBC       | **378 Mbps**  | 66.88 Mbps <br> `5.66x slow` | 136 Mbps <br> `2.77x slow`       |
| AES-192/CBC       | **351 Mbps**  | 59.4 Mbps <br> `5.92x slow`  | 130 Mbps <br> `2.7x slow`        |
| AES-256/CBC       | **310 Mbps**  | 56.3 Mbps <br> `5.51x slow`  | 122 Mbps <br> `2.55x slow`       |
| AES-128/CTR       | **443 Mbps**  | 66.25 Mbps <br> `6.69x slow` | 78.06 Mbps <br> `5.68x slow`     |
| AES-192/CTR       | **408 Mbps**  | 59.01 Mbps <br> `6.91x slow` | 75.84 Mbps <br> `5.38x slow`     |
| AES-256/CTR       | **351 Mbps**  | 56.3 Mbps <br> `6.23x slow`  | 73.8 Mbps <br> `4.76x slow`      |
| AES-128/GCM       | 33.54 Mbps    | 6.6 Mbps <br> `5.08x slow`   | **51.58 Mbps** <br> `1.54x fast` |
| AES-192/GCM       | 32.95 Mbps    | 6.41 Mbps <br> `5.14x slow`  | **50.12 Mbps** <br> `1.52x fast` |
| AES-256/GCM       | 32.5 Mbps     | 6.31 Mbps <br> `5.15x slow`  | **46.96 Mbps** <br> `1.44x fast` |
| AES-128/CFB       | **378 Mbps**  | 66.12 Mbps <br> `5.71x slow` |                                  |
| AES-192/CFB       | **353 Mbps**  | 59.55 Mbps <br> `5.92x slow` |                                  |
| AES-256/CFB       | **309 Mbps**  | 56.07 Mbps <br> `5.5x slow`  |                                  |
| AES-128/OFB       | **389 Mbps**  | 66.74 Mbps <br> `5.82x slow` |                                  |
| AES-192/OFB       | **361 Mbps**  | 59.78 Mbps <br> `6.04x slow` |                                  |
| AES-256/OFB       | **319 Mbps**  | 56.65 Mbps <br> `5.63x slow` |                                  |
| AES-128/XTS       | **288 Mbps**  |                              |                                  |
| AES-192/XTS       | **276 Mbps**  |                              |                                  |
| AES-256/XTS       | **238 Mbps**  |                              |                                  |
| AES-128/IGE       | **330 Mbps**  | 64.73 Mbps <br> `5.1x slow`  |                                  |
| AES-192/IGE       | **325 Mbps**  | 58.01 Mbps <br> `5.61x slow` |                                  |
| AES-256/IGE       | **288 Mbps**  | 55.34 Mbps <br> `5.2x slow`  |                                  |
| AES-128/PCBC      | **368 Mbps**  |                              |                                  |
| AES-192/PCBC      | **346 Mbps**  |                              |                                  |
| AES-256/PCBC      | **304 Mbps**  |                              |                                  |

> All benchmarks are done on 36GB _Apple M3 Pro_ using compiled _exe_
>
> Dart SDK version: 3.8.1 (stable) (Wed May 28 00:47:25 2025 -0700) on "macos_arm64"
