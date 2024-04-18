# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib
- **PointyCastle** : https://pub.dev/packages/pointycastle
- **Cryptography** : https://pub.dev/packages/cryptography

With 5MB message (10 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`               | `cryptography`               |
| ------------------------- | -------------- | ---------------------------- | ---------------------------- |
| XOR                       | **259.18MB/s** | ➖                           | ➖                           |
| ChaCha20                  | **111.43MB/s** | 32.80MB/s <br> `240% slower` | ➖                           |
| ChaCha20/Poly1305         | **111.40MB/s** | ➖                           | 33.40MB/s <br> `234% slower` |
| ChaCha20/Poly1305(digest) | **264.11MB/s** | ➖                           | ➖                           |
| Salsa20                   | **110.24MB/s** | 30.05MB/s <br> `267% slower` | ➖                           |
| Salsa20/Poly1305          | **110.32MB/s** | ➖                           | ➖                           |
| Salsa20/Poly1305(digest)  | **257.01MB/s** | ➖                           | ➖                           |

With 1KB message (5000 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`               | `cryptography`               |
| ------------------------- | -------------- | ---------------------------- | ---------------------------- |
| XOR                       | **271.84MB/s** | ➖                           | ➖                           |
| ChaCha20                  | **110.43MB/s** | 31.77MB/s <br> `248% slower` | ➖                           |
| ChaCha20/Poly1305         | **110.04MB/s** | ➖                           | 31.16MB/s <br> `253% slower` |
| ChaCha20/Poly1305(digest) | **227.55MB/s** | ➖                           | ➖                           |
| Salsa20                   | **111.28MB/s** | 29.29MB/s <br> `280% slower` | ➖                           |
| Salsa20/Poly1305          | **110.90MB/s** | ➖                           | ➖                           |
| Salsa20/Poly1305(digest)  | **227.78MB/s** | ➖                           | ➖                           |

With 10B message (100000 iterations):

| Algorithms                | `cipherlib`    | `PointyCastle`              | `cryptography`              |
| ------------------------- | -------------- | --------------------------- | --------------------------- |
| XOR                       | **197.94MB/s** | ➖                          | ➖                          |
| ChaCha20                  | **31.49MB/s**  | 4.05MB/s <br> `676% slower` | ➖                          |
| ChaCha20/Poly1305         | **31.73MB/s**  | ➖                          | 4.05MB/s <br> `682% slower` |
| ChaCha20/Poly1305(digest) | **14.46MB/s**  | ➖                          | ➖                          |
| Salsa20                   | **31.76MB/s**  | 3.79MB/s <br> `737% slower` | ➖                          |
| Salsa20/Poly1305          | **32.38MB/s**  | ➖                          | ➖                          |
| Salsa20/Poly1305(digest)  | **14.47MB/s**  | ➖                          | ➖                          |

> All benchmarks are done on _AMD Ryzen 7 5800X_ processor and _3200MHz_ RAM using compiled _exe_
>
> Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
