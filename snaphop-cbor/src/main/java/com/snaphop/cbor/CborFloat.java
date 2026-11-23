package com.snaphop.cbor;

import java.math.BigDecimal;

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
    if (value == 0) {
      return Double.doubleToRawLongBits(value) < 0 ? "-0.0" : "0.0";
    }
    // The shortest decimal that reads back as the same double, written as
    // RFC 8949's examples are: plainly from 1e-6 up to 1e21, otherwise as a
    // mantissa with at least one decimal and a signed exponent.
    BigDecimal d = new BigDecimal(Double.toString(value));
    double magnitude = Math.abs(value);
    if (magnitude >= 1e-6 && magnitude < 1e21) {
      String plain = d.stripTrailingZeros().toPlainString();
      return plain.contains(".") ? plain : plain + ".0";
    }
    String digits = d.unscaledValue().abs().toString().replaceAll("0+$", "");
    if (digits.isEmpty()) {
      digits = "0";
    }
    int exponent = d.precision() - d.scale() - 1;
    String mantissa = digits.charAt(0) + "." + (digits.length() > 1 ? digits.substring(1) : "0");
    return (value < 0 ? "-" : "") + mantissa + "e" + (exponent >= 0 ? "+" : "-") + Math.abs(exponent);
  }
}
