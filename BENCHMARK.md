# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib
- **PointyCastle** : https://pub.dev/packages/pointycastle
- **Cryptography** : https://pub.dev/packages/cryptography

With 5MB message (10 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`               | `cryptography`               |
| ------------------------- | -------------- | ---------------------------- | ---------------------------- |
| XOR                       | **229.41MB/s** | ➖                           | ➖                           |
| AES-128                   | **127.14MB/s** | ➖                           | ➖                           |
| ChaCha20                  | **108MB/s**    | 31.04MB/s <br> `248% slower` | ➖                           |
| ChaCha20/Poly1305         | **76.11MB/s**  | ➖                           | 32.82MB/s <br> `132% slower` |
| ChaCha20/Poly1305(digest) | **260.60MB/s** | ➖                           | ➖                           |
| Salsa20                   | **107.58MB/s** | 29.96MB/s <br> `259% slower` | ➖                           |
| Salsa20/Poly1305          | **75.55MB/s**  | ➖                           | ➖                           |
| Salsa20/Poly1305(digest)  | **258.42MB/s** | ➖                           | ➖                           |

With 1KB message (5000 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`               | `cryptography`               |
| ------------------------- | -------------- | ---------------------------- | ---------------------------- |
| XOR                       | **241.19MB/s** | ➖                           | ➖                           |
| AES-128                   | **130.11MB/s** | ➖                           | ➖                           |
| ChaCha20                  | **109.99MB/s** | 31.18MB/s <br> `253% slower` | ➖                           |
| ChaCha20/Poly1305         | **72.65MB/s**  | ➖                           | 31.21MB/s <br> `133% slower` |
| ChaCha20/Poly1305(digest) | **224.34MB/s** | ➖                           | ➖                           |
| Salsa20                   | **108.12MB/s** | 29.63MB/s <br> `265% slower` | ➖                           |
| Salsa20/Poly1305          | **71.65MB/s**  | ➖                           | ➖                           |
| Salsa20/Poly1305(digest)  | **225.91MB/s** | ➖                           | ➖                           |

With 16B message (100000 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`              | `cryptography`              |
| ------------------------- | -------------- | --------------------------- | --------------------------- |
| XOR                       | **200.30MB/s** | ➖                          | ➖                          |
| AES-128                   | **75.92MB/s**  | ➖                          | ➖                          |
| ChaCha20                  | **47.21MB/s**  | 5.56MB/s <br> `749% slower` | ➖                          |
| ChaCha20/Poly1305         | **15.43MB/s**  | ➖                          | 6.50MB/s <br> `137% slower` |
| ChaCha20/Poly1305(digest) | **23.68MB/s**  | ➖                          | ➖                          |
| Salsa20                   | **43.13MB/s**  | 6.06MB/s <br> `611% slower` | ➖                          |
| Salsa20/Poly1305          | **14.77MB/s**  | ➖                          | ➖                          |
| Salsa20/Poly1305(digest)  | **22.78MB/s**  | ➖                          | ➖                          |

> All benchmarks are done on _AMD Ryzen 7 5800X_ processor and _3200MHz_ RAM using compiled _exe_
>
> > Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
