package com.snaphop.cbor;

import java.math.BigInteger;

/// An integer: major type 0 (0 to 2^64 - 1) or 1 (-2^64 to -1).
///
/// Bignums (tags 2 and 3) are not integers here: they are a [CborTag]
/// around a [CborBytes].
///
/// @param value the integer, from -2^64 to 2^64 - 1
public record CborInteger(BigInteger value) implements CborValue {

  static final BigInteger MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
  static final BigInteger MIN = BigInteger.ONE.shiftLeft(64).negate();

  /// Checks the range.
  ///
  /// @param value the integer, from -2^64 to 2^64 - 1
  /// @throws IllegalArgumentException outside that range
  public CborInteger {
    if (value.compareTo(MAX) > 0 || value.compareTo(MIN) < 0) {
      throw new IllegalArgumentException("Outside CBOR's integers (-2^64 to 2^64 - 1): " + value);
    }
  }

  /// An integer from a `long`.
  ///
  /// @param value the integer
  /// @return the CBOR integer
  public static CborInteger of(long value) {
    return new CborInteger(BigInteger.valueOf(value));
  }

  /// The value as a `long`.
  ///
  /// @return the value
  /// @throws ArithmeticException if it does not fit in a `long`
  public long longValueExact() {
    return value.longValueExact();
  }

  /// The value as an `int`.
  ///
  /// @return the value
  /// @throws ArithmeticException if it does not fit in an `int`
  public int intValueExact() {
    return value.intValueExact();
  }

  @Override
  public int majorType() {
    return value.signum() < 0 ? 1 : 0;
  }

  @Override
  public String toString() {
    return value.toString();
  }
}
