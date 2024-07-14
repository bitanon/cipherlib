# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib
- **PointyCastle** : https://pub.dev/packages/pointycastle
- **Cryptography** : https://pub.dev/packages/cryptography

With 1MB message (10 iterations):

| Algorithms        | `cipherlib`   | `PointyCastle`                | `cryptography`               |
| ----------------- | ------------- | ----------------------------- | ---------------------------- |
| XOR               | **2.05 Gbps** |                               |                              |
| ChaCha20          | **1.22 Gbps** | 276 Mbps <br> `4.41x slow`    |                              |
| ChaCha20/Poly1305 | **782 Mbps**  | 201 Mbps <br> `3.88x slow`    | 288 Mbps <br> `2.72x slow`   |
| Salsa20           | **1.22 Gbps** | 247 Mbps <br> `4.95x slow`    |                              |
| Salsa20/Poly1305  | **778 Mbps**  |                               |                              |
| AES-128:keygen    | **138 Tbps**  | 23.06 Tbps <br> `5.97x slow`  | 56.09 Tbps <br> `2.45x slow` |
| AES-192:keygen    | **144 Tbps**  | 19.97 Tbps <br> `7.21x slow`  | 50.94 Tbps <br> `2.83x slow` |
| AES-256:keygen    | **110 Tbps**  | 16.62 Tbps <br> `6.63x slow`  | 43.68 Tbps <br> `2.52x slow` |
| AES-128/ECB       | **929 Mbps**  | 172 Mbps <br> `5.41x slow`    |                              |
| AES-192/ECB       | **839 Mbps**  | 148 Mbps <br> `5.66x slow`    |                              |
| AES-256/ECB       | **752 Mbps**  | 133 Mbps <br> `5.65x slow`    |                              |
| AES-128/CBC       | **909 Mbps**  | 160 Mbps <br> `5.67x slow`    | 817 Mbps <br> `1.11x slow`   |
| AES-192/CBC       | **822 Mbps**  | 140 Mbps <br> `5.85x slow`    | 770 Mbps <br> `1.07x slow`   |
| AES-256/CBC       | **754 Mbps**  | 126 Mbps <br> `5.97x slow`    | 710 Mbps <br> `1.06x slow`   |
| AES-128/CTR       | **934 Mbps**  | 158 Mbps <br> `5.91x slow`    | 502 Mbps <br> `1.86x slow`   |
| AES-192/CTR       | **847 Mbps**  | 138 Mbps <br> `6.14x slow`    | 474 Mbps <br> `1.79x slow`   |
| AES-256/CTR       | **769 Mbps**  | 123 Mbps <br> `6.24x slow`    | 447 Mbps <br> `1.72x slow`   |
| AES-128/GCM       | **144 Mbps**  | 12 Mbps <br> `12.02x slow`    | 134 Mbps <br> `1.08x slow`   |
| AES-192/GCM       | **142 Mbps**  | 11.91 Mbps <br> `11.91x slow` | 132 Mbps <br> `1.08x slow`   |
| AES-256/GCM       | **139 Mbps**  | 11.75 Mbps <br> `11.86x slow` | 130 Mbps <br> `1.07x slow`   |
| AES-128/CFB       | **451 Mbps**  | 781 kbps <br> `577.91x slow`  |                              |
| AES-192/CFB       | **412 Mbps**  | 783 kbps <br> `526.15x slow`  |                              |
| AES-256/CFB       | **373 Mbps**  | 780 kbps <br> `478.83x slow`  |                              |
| AES-128/OFB       | **807 Mbps**  | 163 Mbps <br> `4.95x slow`    |                              |
| AES-192/OFB       | **739 Mbps**  | 141 Mbps <br> `5.25x slow`    |                              |
| AES-256/OFB       | **683 Mbps**  | 126 Mbps <br> `5.42x slow`    |                              |
| AES-128/XTS       | **676 Mbps**  |                               |                              |
| AES-192/XTS       | **630 Mbps**  |                               |                              |
| AES-256/XTS       | **584 Mbps**  |                               |                              |
| AES-128/PCBC      | **854 Mbps**  |                               |                              |
| AES-192/PCBC      | **775 Mbps**  |                               |                              |
| AES-256/PCBC      | **711 Mbps**  |                               |                              |

With 5KB message (5000 iterations):

| Algorithms        | `cipherlib`   | `PointyCastle`                | `cryptography`             |
| ----------------- | ------------- | ----------------------------- | -------------------------- |
| XOR               | **2.15 Gbps** |                               |                            |
| ChaCha20          | **1.25 Gbps** | 278 Mbps <br> `4.5x slow`     |                            |
| ChaCha20/Poly1305 | **783 Mbps**  | 199 Mbps <br> `3.93x slow`    | 281 Mbps <br> `2.78x slow` |
| Salsa20           | **1.25 Gbps** | 252 Mbps <br> `4.96x slow`    |                            |
| Salsa20/Poly1305  | **784 Mbps**  |                               |                            |
| AES-128:keygen    | **712 Gbps**  | 117 Gbps <br> `6.09x slow`    | 282 Gbps <br> `2.53x slow` |
| AES-192:keygen    | **748 Gbps**  | 100 Gbps <br> `7.47x slow`    | 255 Gbps <br> `2.94x slow` |
| AES-256:keygen    | **564 Gbps**  | 83.55 Gbps <br> `6.75x slow`  | 219 Gbps <br> `2.58x slow` |
| AES-128/ECB       | **938 Mbps**  | 174 Mbps <br> `5.4x slow`     |                            |
| AES-192/ECB       | **850 Mbps**  | 151 Mbps <br> `5.64x slow`    |                            |
| AES-256/ECB       | **772 Mbps**  | 133 Mbps <br> `5.78x slow`    |                            |
| AES-128/CBC       | **933 Mbps**  | 162 Mbps <br> `5.74x slow`    | 860 Mbps <br> `1.08x slow` |
| AES-192/CBC       | **840 Mbps**  | 142 Mbps <br> `5.9x slow`     | 778 Mbps <br> `1.08x slow` |
| AES-256/CBC       | **762 Mbps**  | 126 Mbps <br> `6.02x slow`    | 709 Mbps <br> `1.07x slow` |
| AES-128/CTR       | **957 Mbps**  | 159 Mbps <br> `6.03x slow`    | 506 Mbps <br> `1.89x slow` |
| AES-192/CTR       | **863 Mbps**  | 139 Mbps <br> `6.2x slow`     | 479 Mbps <br> `1.8x slow`  |
| AES-256/CTR       | **781 Mbps**  | 124 Mbps <br> `6.28x slow`    | 453 Mbps <br> `1.72x slow` |
| AES-128/GCM       | **146 Mbps**  | 11.87 Mbps <br> `12.29x slow` | 138 Mbps <br> `1.06x slow` |
| AES-192/GCM       | **144 Mbps**  | 11.84 Mbps <br> `12.16x slow` | 135 Mbps <br> `1.07x slow` |
| AES-256/GCM       | **141 Mbps**  | 11.67 Mbps <br> `12.08x slow` | 132 Mbps <br> `1.07x slow` |
| AES-128/CFB       | **458 Mbps**  | 142 Mbps <br> `3.23x slow`    |                            |
| AES-192/CFB       | **415 Mbps**  | 126 Mbps <br> `3.29x slow`    |                            |
| AES-256/CFB       | **380 Mbps**  | 114 Mbps <br> `3.35x slow`    |                            |
| AES-128/OFB       | **824 Mbps**  | 164 Mbps <br> `5.01x slow`    |                            |
| AES-192/OFB       | **748 Mbps**  | 144 Mbps <br> `5.2x slow`     |                            |
| AES-256/OFB       | **690 Mbps**  | 127 Mbps <br> `5.45x slow`    |                            |
| AES-128/XTS       | **698 Mbps**  |                               |                            |
| AES-192/XTS       | **644 Mbps**  |                               |                            |
| AES-256/XTS       | **601 Mbps**  |                               |                            |
| AES-128/PCBC      | **852 Mbps**  |                               |                            |
| AES-192/PCBC      | **777 Mbps**  |                               |                            |
| AES-256/PCBC      | **702 Mbps**  |                               |                            |

With 16B message (100000 iterations):

| Algorithms        | `cipherlib`   | `PointyCastle`               | `cryptography`                   |
| ----------------- | ------------- | ---------------------------- | -------------------------------- |
| XOR               | **1.8 Gbps**  |                              |                                  |
| ChaCha20          | **427 Mbps**  | 51.3 Mbps <br> `8.33x slow`  |                                  |
| ChaCha20/Poly1305 | **110 Mbps**  | 44.61 Mbps <br> `2.46x slow` | 35.42 Mbps <br> `3.1x slow`      |
| Salsa20           | **410 Mbps**  | 49.12 Mbps <br> `8.36x slow` |                                  |
| Salsa20/Poly1305  | **106 Mbps**  |                              |                                  |
| AES-128:keygen    | **2.17 Gbps** | 359 Mbps <br> `6.04x slow`   | 850 Mbps <br> `2.55x slow`       |
| AES-192:keygen    | **2.28 Gbps** | 307 Mbps <br> `7.44x slow`   | 782 Mbps <br> `2.92x slow`       |
| AES-256:keygen    | **1.75 Gbps** | 258 Mbps <br> `6.79x slow`   | 675 Mbps <br> `2.59x slow`       |
| AES-128/ECB       | **335 Mbps**  | 54.15 Mbps <br> `6.18x slow` |                                  |
| AES-192/ECB       | **322 Mbps**  | 50.27 Mbps <br> `6.4x slow`  |                                  |
| AES-256/ECB       | **279 Mbps**  | 46.33 Mbps <br> `6.01x slow` |                                  |
| AES-128/CBC       | **301 Mbps**  | 50.75 Mbps <br> `5.93x slow` | 149 Mbps <br> `2.03x slow`       |
| AES-192/CBC       | **289 Mbps**  | 47.15 Mbps <br> `6.14x slow` | 139 Mbps <br> `2.08x slow`       |
| AES-256/CBC       | **259 Mbps**  | 43.69 Mbps <br> `5.92x slow` | 130 Mbps <br> `1.99x slow`       |
| AES-128/CTR       | **498 Mbps**  | 51.14 Mbps <br> `9.75x slow` | 81.76 Mbps <br> `6.1x slow`      |
| AES-192/CTR       | **485 Mbps**  | 47.56 Mbps <br> `10.2x slow` | 79.22 Mbps <br> `6.12x slow`     |
| AES-256/CTR       | **427 Mbps**  | 44.38 Mbps <br> `9.62x slow` | 76.79 Mbps <br> `5.56x slow`     |
| AES-128/GCM       | 27.28 Mbps    | 6.53 Mbps <br> `4.18x slow`  | **42.59 Mbps** <br> `1.56x fast` |
| AES-192/GCM       | 27.29 Mbps    | 6.42 Mbps <br> `4.25x slow`  | **41.49 Mbps** <br> `1.52x fast` |
| AES-256/GCM       | 26.57 Mbps    | 6.29 Mbps <br> `4.23x slow`  | **40.03 Mbps** <br> `1.51x fast` |
| AES-128/CFB       | **314 Mbps**  | 50.7 Mbps <br> `6.2x slow`   |                                  |
| AES-192/CFB       | **292 Mbps**  | 47.38 Mbps <br> `6.17x slow` |                                  |
| AES-256/CFB       | **259 Mbps**  | 44.34 Mbps <br> `5.83x slow` |                                  |
| AES-128/OFB       | **446 Mbps**  | 50.96 Mbps <br> `8.76x slow` |                                  |
| AES-192/OFB       | **428 Mbps**  | 47.28 Mbps <br> `9.06x slow` |                                  |
| AES-256/OFB       | **382 Mbps**  | 44.23 Mbps <br> `8.64x slow` |                                  |
| AES-128/XTS       | **238 Mbps**  |                              |                                  |
| AES-192/XTS       | **227 Mbps**  |                              |                                  |
| AES-256/XTS       | **201 Mbps**  |                              |                                  |
| AES-128/PCBC      | **292 Mbps**  |                              |                                  |
| AES-192/PCBC      | **293 Mbps**  |                              |                                  |
| AES-256/PCBC      | **251 Mbps**  |                              |                                  |

> > Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
