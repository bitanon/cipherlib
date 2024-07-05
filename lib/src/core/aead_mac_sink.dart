// Copyright (c) 2024, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

import 'package:hashlib/hashlib.dart' show HashDigest, MACSinkBase;

/// Extends the base [MACSinkForAEAD] to generate message digest for cipher
/// algorithms.
class MACSinkForAEAD implements MACSinkBase {
  final Uint8List _aad;
  final MACSinkBase _algo;
  int _messageLength = 0;

  MACSinkForAEAD(this._algo, [List<int>? aad])
      : _aad = aad is Uint8List ? aad : Uint8List.fromList(aad ?? []);

  @override
  bool get closed => _algo.closed;

  @override
  int get hashLength => _algo.hashLength;

  @override
  int get derivedKeyLength => _algo.derivedKeyLength;

  @override
  void reset() => _algo.reset();

  @override
  void close() => digest();

  @override
  void init(List<int> keypair) {
    _algo.init(keypair);
    if (_aad.isNotEmpty) {
      _algo.add(_aad);
      if (_aad.length & 15 != 0) {
        _algo.add(Uint8List(16 - (_aad.length & 15)));
      }
    }
    _messageLength = 0;
  }

  @override
  void add(List<int> data, [int start = 0, int? end]) {
    end ??= data.length;
    _messageLength += end - start;
    _algo.add(data, start, end);
  }

  @override
  HashDigest digest() {
    if (_algo.closed) {
      return _algo.digest();
    }
    if (_messageLength & 15 != 0) {
      _algo.add(Uint8List(16 - (_messageLength & 15)));
    }
    _algo.add(Uint32List.fromList([
      _aad.length,
      _aad.length >>> 32,
      _messageLength,
      _messageLength >>> 32,
    ]).buffer.asUint8List());
    return _algo.digest();
  }
}
