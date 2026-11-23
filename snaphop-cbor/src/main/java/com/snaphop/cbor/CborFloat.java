package com.snaphop.cbor;

/// A floating-point number: major type 7, written in 16, 32 or 64 bits.
///
/// How many bits it was written in is not part of the value: `1.5` is the
/// same in all three. NaN equals NaN, and `0.0` does not equal `-0.0`, as
/// with [Double#compare(double, double)].
///
/// @param value the number
public record CborFloat(double value) implements CborValue {

  @Override
  public int majorType() {
    return 7;
  }

  @Override
  public String toString() {
    if (Double.isNaN(value)) {
      return "NaN";
    }
    if (Double.isInfinite(value)) {
      return value > 0 ? "Infinity" : "-Infinity";
    }
    return Double.toString(value);
  }
}
