package com.snaphop.cbor;

/// A simple value: major type 7, other than floats. `false`, `true`, `null`
/// and `undefined` are simple values 20 to 23.
///
/// @param value 0 to 23, or 32 to 255
public record CborSimple(int value) implements CborValue {

  /// `false`, simple value 20.
  public static final CborSimple FALSE = new CborSimple(20);
  /// `true`, simple value 21.
  public static final CborSimple TRUE = new CborSimple(21);
  /// `null`, simple value 22.
  public static final CborSimple NULL = new CborSimple(22);
  /// `undefined`, simple value 23.
  public static final CborSimple UNDEFINED = new CborSimple(23);

  /// Checks the range.
  ///
  /// @param value 0 to 23, or 32 to 255
  /// @throws IllegalArgumentException for 24 to 31 (which are not well-formed)
  ///     or outside 0 to 255
  public CborSimple {
    if (value < 0 || value > 255 || (value >= 24 && value < 32)) {
      throw new IllegalArgumentException("Not a CBOR simple value: " + value);
    }
  }

  @Override
  public int majorType() {
    return 7;
  }

  @Override
  public String toString() {
    return switch (value) {
      case 20 -> "false";
      case 21 -> "true";
      case 22 -> "null";
      case 23 -> "undefined";
      default -> "simple(" + value + ")";
    };
  }
}
