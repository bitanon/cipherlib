# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib

With 5MB message (10 iterations):

| Algorithms                | `cipherlib`    |
| ------------------------- | -------------- |
| XOR                       | **235.83MB/s** |
| ChaCha20                  | **108.76MB/s** |
| ChaCha20/Poly1305         | **76.83MB/s**  |
| ChaCha20/Poly1305(digest) | **249.10MB/s** |

With 1KB message (5000 iterations):

| Algorithms                | `cipherlib`    |
| ------------------------- | -------------- |
| XOR                       | **257.71MB/s** |
| ChaCha20                  | **112.43MB/s** |
| ChaCha20/Poly1305         | **74.40MB/s**  |
| ChaCha20/Poly1305(digest) | **210.84MB/s** |

With 10B message (100000 iterations):

| Algorithms                | `cipherlib`    |
| ------------------------- | -------------- |
| XOR                       | **183.72MB/s** |
| ChaCha20                  | **30.74MB/s**  |
| ChaCha20/Poly1305         | **9.59MB/s**   |
| ChaCha20/Poly1305(digest) | **14.06MB/s**  |

> All benchmarks are done on _AMD Ryzen 7 5800X_ processor and _3200MHz_ RAM using compiled _exe_
>
> Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
