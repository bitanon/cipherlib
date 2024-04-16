# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib

With 5MB message (10 iterations):

| Algorithms                | `cipherlib`    |
| ------------------------- | -------------- |
| XOR                       | **248.44MB/s** |
| ChaCha20                  | **110.88MB/s** |
| ChaCha20/Poly1305         | **76.16MB/s**  |
| ChaCha20/Poly1305(digest) | **234.77MB/s** |
| Salsa20                   | **106.55MB/s** |
| Salsa20/Poly1305          | **77.52MB/s**  |
| Salsa20/Poly1305(digest)  | **222.87MB/s** |

With 1KB message (5000 iterations):

| Algorithms                | `cipherlib`    |
| ------------------------- | -------------- |
| XOR                       | **261.23MB/s** |
| ChaCha20                  | **111.55MB/s** |
| ChaCha20/Poly1305         | **71.73MB/s**  |
| ChaCha20/Poly1305(digest) | **205.61MB/s** |
| Salsa20                   | **113.03MB/s** |
| Salsa20/Poly1305          | **72.21MB/s**  |
| Salsa20/Poly1305(digest)  | **198.92MB/s** |

With 10B message (100000 iterations):

| Algorithms                | `cipherlib`    |
| ------------------------- | -------------- |
| XOR                       | **191.96MB/s** |
| ChaCha20                  | **30.81MB/s**  |
| ChaCha20/Poly1305         | **9.57MB/s**   |
| ChaCha20/Poly1305(digest) | **14.25MB/s**  |
| Salsa20                   | **30.58MB/s**  |
| Salsa20/Poly1305          | **9.49MB/s**   |
| Salsa20/Poly1305(digest)  | **13.94MB/s**  |

> All benchmarks are done on _AMD Ryzen 7 5800X_ processor and _3200MHz_ RAM using compiled _exe_
>
> Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
