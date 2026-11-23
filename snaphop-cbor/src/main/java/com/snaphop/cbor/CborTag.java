package com.snaphop.cbor;

/// A tagged value: major type 6.
///
/// The reader does not interpret tags: a date (tag 0) or a bignum (tag 2)
/// comes back as the tag and its content.
///
/// @param number the tag number, 0 to 2^64 - 1 read as unsigned
/// @param content the tagged value
public record CborTag(long number, CborValue content) implements CborValue {

  @Override
  public int majorType() {
    return 6;
  }

  @Override
  public String toString() {
    return Long.toUnsignedString(number) + "(" + content + ")";
  }
}
