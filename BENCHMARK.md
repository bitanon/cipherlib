# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib

With 5MB message (10 iterations):

| Algorithms | `cipherlib[key:10B]` | `cipherlib[key:1KB]` | `cipherlib[key:5MB]` |
|------------|----------------------|----------------------|----------------------|
| XOR      | **246.28MB/s** | 245.36MB/s | 245.48MB/s |
| XOR(pipe)      | 70.81TB/s | **70.98TB/s** | 70.84TB/s |

With 1KB message (5000 iterations):

| Algorithms | `cipherlib[key:10B]` | `cipherlib[key:1KB]` | `cipherlib[key:5MB]` |
|------------|----------------------|----------------------|----------------------|
| XOR      | 256.42MB/s | 256.41MB/s | **256.65MB/s** |
| XOR(pipe)      | 14.34GB/s | 14.38GB/s | **14.44GB/s** <br> `1% faster` |

With 10B message (100000 iterations):

| Algorithms | `cipherlib[key:10B]` | `cipherlib[key:1KB]` | `cipherlib[key:5MB]` |
|------------|----------------------|----------------------|----------------------|
| XOR      | 185.24MB/s | **186.45MB/s** <br> `1% faster` | 186.28MB/s <br> `1% faster` |
| XOR(pipe)      | **144.20MB/s** | 143.58MB/s | 141.57MB/s <br> `2% slower` |

> All benchmarks are done on _AMD Ryzen 7 5800X_ processor and _3200MHz_ RAM using compiled _exe_
> <br>> Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
