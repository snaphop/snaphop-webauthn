package com.snaphop.cbor;

/// A text string: major type 3, always valid UTF-8 when read.
///
/// @param value the text
public record CborText(String value) implements CborValue {

  @Override
  public int majorType() {
    return 3;
  }

  @Override
  public String toString() {
    StringBuilder b = new StringBuilder(value.length() + 2).append('"');
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '"' -> b.append("\\\"");
        case '\\' -> b.append("\\\\");
        case '\n' -> b.append("\\n");
        case '\r' -> b.append("\\r");
        case '\t' -> b.append("\\t");
        default -> {
          if (c < 0x20 || c == 0x7f) {
            b.append(String.format("\\u%04x", (int) c));
          } else {
            b.append(c);
          }
        }
      }
    }
    return b.append('"').toString();
  }
}
