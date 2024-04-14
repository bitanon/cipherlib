# Benchmarks

Libraries:

- **Cipherlib** : https://pub.dev/packages/cipherlib

With 5MB message (10 iterations):

| Algorithms     | `cipherlib`    |
| -------------- | -------------- |
| XOR            | **243.84MB/s** |
| XOR(pipe)      | **66.57TB/s**  |
| ChaCha20       | **125.40MB/s** |
| ChaCha20(pipe) | **58.43TB/s**  |

With 1KB message (5000 iterations):

| Algorithms     | `cipherlib`    |
| -------------- | -------------- |
| XOR            | **266.28MB/s** |
| XOR(pipe)      | **13.71GB/s**  |
| ChaCha20       | **129.03MB/s** |
| ChaCha20(pipe) | **11.86GB/s**  |

With 10B message (100000 iterations):

| Algorithms     | `cipherlib`    |
| -------------- | -------------- |
| XOR            | **190.05MB/s** |
| XOR(pipe)      | **136.98MB/s** |
| ChaCha20       | **31.78MB/s**  |
| ChaCha20(pipe) | **118.66MB/s** |

> All benchmarks are done on _AMD Ryzen 7 5800X_ processor and _3200MHz_ RAM using compiled _exe_
>
> Dart SDK version: 3.3.3 (stable) (Tue Mar 26 14:21:33 2024 +0000) on "windows_x64"
