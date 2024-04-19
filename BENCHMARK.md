# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib
- **PointyCastle** : https://pub.dev/packages/pointycastle
- **Cryptography** : https://pub.dev/packages/cryptography

With 5MB message (10 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`               | `cryptography`               |
| ------------------------- | -------------- | ---------------------------- | ---------------------------- |
| XOR                       | **241MB/s**    | ➖                           | ➖                           |
| ChaCha20                  | **107.60MB/s** | 30.48MB/s <br> `253% slower` | ➖                           |
| ChaCha20/Poly1305         | **75.32MB/s**  | ➖                           | 33.24MB/s <br> `127% slower` |
| ChaCha20/Poly1305(digest) | **247.47MB/s** | ➖                           | ➖                           |
| Salsa20                   | **107.24MB/s** | 27.91MB/s <br> `284% slower` | ➖                           |
| Salsa20/Poly1305          | **76.42MB/s**  | ➖                           | ➖                           |
| Salsa20/Poly1305(digest)  | **248.50MB/s** | ➖                           | ➖                           |

With 1KB message (5000 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`               | `cryptography`               |
| ------------------------- | -------------- | ---------------------------- | ---------------------------- |
| XOR                       | **250.20MB/s** | ➖                           | ➖                           |
| ChaCha20                  | **108.38MB/s** | 30.87MB/s <br> `251% slower` | ➖                           |
| ChaCha20/Poly1305         | **71.48MB/s**  | ➖                           | 31.39MB/s <br> `128% slower` |
| ChaCha20/Poly1305(digest) | **213.58MB/s** | ➖                           | ➖                           |
| Salsa20                   | **108.21MB/s** | 29.29MB/s <br> `269% slower` | ➖                           |
| Salsa20/Poly1305          | **72.17MB/s**  | ➖                           | ➖                           |
| Salsa20/Poly1305(digest)  | **217.38MB/s** | ➖                           | ➖                           |

With 10B message (100000 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`              | `cryptography`              |
| ------------------------- | -------------- | --------------------------- | --------------------------- |
| XOR                       | **185.62MB/s** | ➖                          | ➖                          |
| ChaCha20                  | **32.03MB/s**  | 3.91MB/s <br> `719% slower` | ➖                          |
| ChaCha20/Poly1305         | **9.71MB/s**   | ➖                          | 4.14MB/s <br> `134% slower` |
| ChaCha20/Poly1305(digest) | **14.31MB/s**  | ➖                          | ➖                          |
| Salsa20                   | **32.33MB/s**  | 3.81MB/s <br> `748% slower` | ➖                          |
| Salsa20/Poly1305          | **9.81MB/s**   | ➖                          | ➖                          |
| Salsa20/Poly1305(digest)  | **14.25MB/s**  | ➖                          | ➖                          |

> All benchmarks are done on _AMD Ryzen 7 5800X_ processor and _3200MHz_ RAM using compiled _exe_
>
> Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
