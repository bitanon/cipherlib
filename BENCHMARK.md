# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib
- **PointyCastle** : https://pub.dev/packages/pointycastle
- **Cryptography** : https://pub.dev/packages/cryptography

With 1MB message (10 iterations):

| Algorithms        | `cipherlib`   | `PointyCastle`                | `cryptography`              |
| ----------------- | ------------- | ----------------------------- | --------------------------- |
| XOR               | **6.18 Gbps** |                               |                             |
| ChaCha20          | **1.37 Gbps** | 307 Mbps <br> `4.46x slow`    |                             |
| ChaCha20/Poly1305 | **940 Mbps**  | 228 Mbps <br> `4.13x slow`    | 256 Mbps <br> `3.67x slow`  |
| Salsa20           | **1.45 Gbps** | 303 Mbps <br> `4.8x slow`     |                             |
| Salsa20/Poly1305  | **989 Mbps**  |                               |                             |
| AES-128/ECB       | **1.2 Gbps**  | 199 Mbps <br> `6.04x slow`    |                             |
| AES-192/ECB       | **1.06 Gbps** | 192 Mbps <br> `5.49x slow`    |                             |
| AES-256/ECB       | **955 Mbps**  | 171 Mbps <br> `5.58x slow`    |                             |
| AES-128/CBC       | **1.23 Gbps** | 204 Mbps <br> `5.65x slow`    | 1.15 Gbps <br> `1.07x slow` |
| AES-192/CBC       | **1.08 Gbps** | 182 Mbps <br> `5.77x slow`    | 1.05 Gbps <br> `1.02x slow` |
| AES-256/CBC       | **965 Mbps**  | 163 Mbps <br> `5.67x slow`    | 927 Mbps <br> `1.04x slow`  |
| AES-128/CTR       | **1.13 Gbps** | 201 Mbps <br> `5.61x slow`    | 579 Mbps <br> `1.95x slow`  |
| AES-192/CTR       | **1 Gbps**    | 178 Mb                        |                             |
| AES-128/CFB       | **579 Mbps**  | 3.11 Mbps <br> `185.87x slow` |                             |
| AES-192/CFB       | **510 Mbps**  | 3.1 Mbps <br> `164.63x slow`  |                             |
| AES-256/CFB       | **463 Mbps**  | 3.16 Mbps <br> `146.64x slow` |                             |
| AES-128/OFB       | **1.07 Gbps** | 212 Mbps <br> `5.06x slow`    |                             |
| AES-192/OFB       | **936 Mbps**  | 187 Mbps <br> `5.01x slow`    |                             |
| AES-256/OFB       | **874 Mbps**  | 167 Mbps <br> `5.23x slow`    |                             |
| AES-128/XTS       | **792 Mbps**  |                               |                             |
| AES-192/XTS       | **729 Mbps**  |                               |                             |
| AES-256/XTS       | **680 Mbps**  |                               |                             |
| AES-128/IGE       | **1.05 Gbps** | 196 Mbps <br> `5.35x slow`    |                             |
| AES-192/IGE       | **928 Mbps**  | 174 Mbps <br> `5.33x slow`    |                             |
| AES-256/IGE       | **850 Mbps**  | 157 Mbps <br> `5.42x slow`    |                             |
| AES-128/PCBC      | **1.05 Gbps** |                               |                             |
| AES-192/PCBC      | **951 Mbps**  |                               |                             |
| AES-256/PCBC      | **862 Mbps**  |                               |                             |

With 5KB message (5000 iterations):

| Algorithms        | `cipherlib`   | `PointyCastle`                | `cryptography`              |
| ----------------- | ------------- | ----------------------------- | --------------------------- |
| XOR               | **7.36 Gbps** |                               |                             |
| ChaCha20          | **1.46 Gbps** | 320 Mbps <br> `4.55x slow`    |                             |
| ChaCha20/Poly1305 | **947 Mbps**  | 251 Mbps <br> `3.77x slow`    | 255 Mbps <br> `3.71x slow`  |
| Salsa20           | **1.53 Gbps** | 315 Mbps <br> `4.85x slow`    |                             |
| Salsa20/Poly1305  | **999 Mbps**  |                               |                             |
| AES-128/ECB       | **1.18 Gbps** | 233 Mbps <br> `5.06x slow`    |                             |
| AES-192/ECB       | **1.05 Gbps** | 199 Mbps <br> `5.27x slow`    |                             |
| AES-256/ECB       | **950 Mbps**  | 179 Mbps <br> `5.32x slow`    |                             |
| AES-128/CBC       | **1.23 Gbps** | 219 Mbps <br> `5.42x slow`    | 1.19 Gbps <br> `1.04x slow` |
| AES-192/CBC       | **1.08 Gbps** | 192 Mbps <br> `5.44x slow`    | 1.04 Gbps <br> `1.03x slow` |
| AES-256/CBC       | **950 Mbps**  | 171 Mbps <br> `5.54x slow`    | 946 Mbps <br> `1.01x slow`  |
| AES-128/CTR       | **1.14 Gbps** | 211 Mbps <br> `5.4x slow`     | 600 Mbps <br> `1.9x slow`   |
| AES-192/CTR       | **1.01 Gbps** | 186 Mbps <br> `5.44x slow`    | 562 Mbps <br> `1.8x slow`   |
| AES-256/CTR       | **919 Mbps**  | 166 Mbps <br> `5.53x slow`    | 527 Mbps <br> `1.74x slow`  |
| AES-128/GCM       | **266 Mbps**  | 13.04 Mbps <br> `20.36x slow` | 217 Mbps <br> `1.22x slow`  |
| AES-192/GCM       | **256 Mbps**  | 12.92 Mbps <br> `19.84x slow` | 223 Mbps <br> `1.15x slow`  |
| AES-256/GCM       | **241 Mbps**  | 12.77 Mbps <br> `18.89x slow` | 216 Mbps <br> `1.12x slow`  |
| AES-128/CFB       | **578 Mbps**  | 188 Mbps <br> `3.08x slow`    |                             |
| AES-192/CFB       | **510 Mbps**  | 167 Mbps <br> `3.06x slow`    |                             |
| AES-256/CFB       | **463 Mbps**  | 151 Mbps <br> `3.07x slow`    |                             |
| AES-128/OFB       | **1.07 Gbps** | 226 Mbps <br> `4.72x slow`    |                             |
| AES-192/OFB       | **952 Mbps**  | 197 Mbps <br> `4.83x slow`    |                             |
| AES-256/OFB       | **871 Mbps**  | 175 Mbps <br> `4.98x slow`    |                             |
| AES-128/XTS       | **797 Mbps**  |                               |                             |
| AES-192/XTS       | **728 Mbps**  |                               |                             |
| AES-256/XTS       | **674 Mbps**  |                               |                             |
| AES-128/IGE       | **1.04 Gbps** | 206 Mbps <br> `5.07x slow`    |                             |
| AES-192/IGE       | **937 Mbps**  | 182 Mbps <br> `5.15x slow`    |                             |
| AES-256/IGE       | **843 Mbps**  | 163 Mbps <br> `5.18x slow`    |                             |
| AES-128/PCBC      | **1.04 Gbps** |                               |                             |
| AES-192/PCBC      | **944 Mbps**  |                               |                             |
| AES-256/PCBC      | **859 Mbps**  |                               |                             |

With 16B message (100000 iterations):

| Algorithms        | `cipherlib`   | `PointyCastle`               | `cryptography`                   |
| ----------------- | ------------- | ---------------------------- | -------------------------------- |
| XOR               | **5.25 Gbps** |                              |                                  |
| ChaCha20          | **443 Mbps**  | 66.87 Mbps <br> `6.62x slow` |                                  |
| ChaCha20/Poly1305 | **146 Mbps**  | 59.14 Mbps <br> `2.47x slow` | 39.29 Mbps <br> `3.72x slow`     |
| Salsa20           | **474 Mbps**  | 66.47 Mbps <br> `7.13x slow` |                                  |
| Salsa20/Poly1305  | **156 Mbps**  |                              |                                  |
| AES-128/ECB       | **420 Mbps**  | 70.84 Mbps <br> `5.93x slow` |                                  |
| AES-192/ECB       | **389 Mbps**  | 63.08 Mbps <br> `6.16x slow` |                                  |
| AES-256/ECB       | **339 Mbps**  | 59.04 Mbps <br> `5.74x slow` |                                  |
| AES-128/CBC       | **376 Mbps**  | 67.1 Mbps <br> `5.61x slow`  | 164 Mbps <br> `2.29x slow`       |
| AES-192/CBC       | **355 Mbps**  | 60.14 Mbps <br> `5.91x slow` | 156 Mbps <br> `2.28x slow`       |
| AES-256/CBC       | **310 Mbps**  | 56.74 Mbps <br> `5.46x slow` | 144 Mbps <br> `2.15x slow`       |
| AES-128/CTR       | **442 Mbps**  | 66.71 Mbps <br> `6.62x slow` | 89.87 Mbps <br> `4.91x slow`     |
| AES-192/CTR       | **411 Mbps**  | 59.46 Mbps <br> `6.91x slow` | 87.79 Mbps <br> `4.68x slow`     |
| AES-256/CTR       | **350 Mbps**  | 56.14 Mbps <br> `6.23x slow` | 84.64 Mbps <br> `4.13x slow`     |
| AES-128/GCM       | 34.21 Mbps    | 6.57 Mbps <br> `5.21x slow`  | **55.41 Mbps** <br> `1.62x fast` |
| AES-192/GCM       | 33.7 Mbps     | 6.33 Mbps <br> `5.33x slow`  | **53.6 Mbps** <br> `1.59x fast`  |
| AES-256/GCM       | 33.13 Mbps    | 6.29 Mbps <br> `5.26x slow`  | **50.12 Mbps** <br> `1.51x fast` |
| AES-128/CFB       | **376 Mbps**  | 66.78 Mbps <br> `5.64x slow` |                                  |
| AES-192/CFB       | **353 Mbps**  | 59.97 Mbps <br> `5.88x slow` |                                  |
| AES-256/CFB       | **307 Mbps**  | 56.24 Mbps <br> `5.47x slow` |                                  |
| AES-128/OFB       | **389 Mbps**  | 67.39 Mbps <br> `5.77x slow` |                                  |
| AES-192/OFB       | **365 Mbps**  | 60.44 Mbps <br> `6.04x slow` |                                  |
| AES-256/OFB       | **320 Mbps**  | 56.5 Mbps <br> `5.67x slow`  |                                  |
| AES-128/XTS       | **287 Mbps**  |                              |                                  |
| AES-192/XTS       | **278 Mbps**  |                              |                                  |
| AES-256/XTS       | **236 Mbps**  |                              |                                  |
| AES-128/IGE       | **348 Mbps**  | 64.22 Mbps <br> `5.42x slow` |                                  |
| AES-192/IGE       | **323 Mbps**  | 58.74 Mbps <br> `5.49x slow` |                                  |
| AES-256/IGE       | **290 Mbps**  | 55.44 Mbps <br> `5.23x slow` |                                  |
| AES-128/PCBC      | **369 Mbps**  |                              |                                  |
| AES-192/PCBC      | **347 Mbps**  |                              |                                  |
| AES-256/PCBC      | **304 Mbps**  |                              |                                  |

> All benchmarks are done on 36GB _Apple M3 Pro_ using compiled _exe_
>
> Dart SDK version: 3.8.1 (stable) (Wed May 28 00:47:25 2025 -0700) on "macos_arm64"
