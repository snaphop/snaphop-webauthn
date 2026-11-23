/// Reads CBOR (RFC 8949) into immutable values.
///
/// Start with [com.snaphop.cbor.CborReader#builder()].
///
/// The module has no runtime dependencies. JSpecify nullness annotations are
/// part of the API but only needed at compile time, so the module requires them
/// as `static transitive`.
///
/// Thread safety: builders are the only mutable types. Readers and every value
/// they read are immutable and thread-safe.
module com.snaphop.cbor {
  exports com.snaphop.cbor;

  requires static transitive org.jspecify;
}
