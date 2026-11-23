/// Reads CBOR (RFC 8949) into immutable values, for input nobody vouches for.
///
/// The types, in the order a caller meets them:
///
/// 1. [CborReader] reads bytes, configured by its builder.
/// 2. [CborValue] is what was read: one of [CborInteger], [CborBytes],
///    [CborText], [CborArray], [CborMap], [CborTag], [CborSimple] or
///    [CborFloat].
/// 3. [CborParseException] reports bytes that are not well-formed or not
///    valid CBOR, with the offset of the problem.
///
/// What the reader refuses, in every mode:
///
/// - anything that is not well-formed (RFC 8949 section 5.3.1 and appendix F);
/// - text strings that are not UTF-8;
/// - maps with the same key twice;
/// - nesting deeper than the reader's limit, and lengths longer than what is
///   left of the input (checked before anything is allocated);
/// - bytes after the item, unless reading a prefix
///   ([CborReader#readPrefix(byte[], int)]).
@org.jspecify.annotations.NullMarked
package com.snaphop.cbor;
