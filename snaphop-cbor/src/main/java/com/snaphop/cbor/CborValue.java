package com.snaphop.cbor;

/// One CBOR data item, as read by [CborReader].
///
/// Values compare by what they mean in CBOR's data model, not by how they
/// were encoded: `1` written in one byte and in nine bytes are equal, as
/// are a byte string written whole and the same bytes in chunks. Their
/// `toString()` is CBOR's diagnostic notation (RFC 8949 section 8), such as
/// `{1: 2, 3: -7, -1: h'0a0b'}`.
public sealed interface CborValue
    permits CborInteger, CborBytes, CborText, CborArray, CborMap, CborTag, CborSimple, CborFloat {

  /// The major type this value is written with, 0 to 7.
  ///
  /// Integers are 0 when not negative and 1 when negative.
  ///
  /// @return the major type
  int majorType();
}
