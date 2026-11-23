package com.snaphop.cbor;

import java.util.List;
import java.util.stream.Collectors;

/// An array: major type 4.
///
/// @param items the items, in order
public record CborArray(List<CborValue> items) implements CborValue {

  /// Copies the items.
  ///
  /// @param items the items, in order
  public CborArray {
    items = List.copyOf(items);
  }

  @Override
  public int majorType() {
    return 4;
  }

  @Override
  public String toString() {
    return items.stream().map(Object::toString).collect(Collectors.joining(", ", "[", "]"));
  }
}
