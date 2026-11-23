package com.snaphop.cbor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.jspecify.annotations.Nullable;

/// A map: major type 5, its entries in the order they were written.
///
/// Keys are unique: [CborReader] refuses a map with the same key twice, and
/// so does this constructor.
///
/// @param entries the entries, in order
public record CborMap(List<Entry> entries) implements CborValue {

  /// Copies the entries and checks the keys are unique.
  ///
  /// @param entries the entries, in order
  /// @throws IllegalArgumentException if a key is there twice
  public CborMap {
    entries = List.copyOf(entries);
    Map<CborValue, Entry> seen = HashMap.newHashMap(entries.size());
    for (Entry e : entries) {
      if (seen.putIfAbsent(e.key(), e) != null) {
        throw new IllegalArgumentException("The key " + e.key() + " is in the map twice");
      }
    }
  }

  /// One key and its value.
  ///
  /// @param key the key
  /// @param value the value
  public record Entry(CborValue key, CborValue value) {}

  /// The value of a key, or null when it isn't there.
  ///
  /// @param key the key
  /// @return the value, or null
  public @Nullable CborValue getOrNull(CborValue key) {
    for (Entry e : entries) {
      if (e.key().equals(key)) {
        return e.value();
      }
    }
    return null;
  }

  /// The value of an integer key, or null when it isn't there.
  ///
  /// @param key the key, such as COSE's `1` (kty) or `-1` (crv)
  /// @return the value, or null
  public @Nullable CborValue getOrNull(long key) {
    return getOrNull(CborInteger.of(key));
  }

  /// The value of a text key, or null when it isn't there.
  ///
  /// @param key the key, such as `"fmt"`
  /// @return the value, or null
  public @Nullable CborValue getOrNull(String key) {
    return getOrNull(new CborText(key));
  }

  /// How many entries there are.
  ///
  /// @return the size
  public int size() {
    return entries.size();
  }

  @Override
  public int majorType() {
    return 5;
  }

  @Override
  public String toString() {
    return entries.stream().map(e -> e.key() + ": " + e.value()).collect(Collectors.joining(", ", "{", "}"));
  }
}
