package com.snaphop.cbor;

import java.util.Arrays;
import java.util.HexFormat;

/// A byte string: major type 2.
///
/// Immutable: the bytes are copied in and copied out.
public final class CborBytes implements CborValue {

  private final byte[] bytes;

  private CborBytes(byte[] bytes) {
    this.bytes = bytes;
  }

  /// A byte string holding a copy of the given bytes.
  ///
  /// @param bytes the bytes
  /// @return the byte string
  public static CborBytes of(byte[] bytes) {
    return new CborBytes(bytes.clone());
  }

  static CborBytes owning(byte[] bytes) {
    return new CborBytes(bytes);
  }

  /// A copy of the bytes.
  ///
  /// @return the bytes
  public byte[] bytes() {
    return bytes.clone();
  }

  /// How many bytes there are.
  ///
  /// @return the length
  public int length() {
    return bytes.length;
  }

  @Override
  public int majorType() {
    return 2;
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof CborBytes b && Arrays.equals(bytes, b.bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }

  @Override
  public String toString() {
    return "h'" + HexFormat.of().formatHex(bytes) + "'";
  }
}
