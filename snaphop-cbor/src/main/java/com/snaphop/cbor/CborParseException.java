package com.snaphop.cbor;

import java.io.Serial;

/// Bytes [CborReader] refuses: not well-formed, not valid, not in the
/// reader's mode, or past one of its limits.
///
/// The message says what was wrong and where, such as
/// `Not well-formed CBOR at byte 3: additional information 28 is reserved (major type 0)`.
public final class CborParseException extends RuntimeException {

  @Serial private static final long serialVersionUID = 1L;

  /// Where the problem is.
  private final int offset;
  /// The problem, without where.
  private final String problem;

  CborParseException(int offset, String kind, String problem) {
    super(kind + " at byte " + offset + ": " + problem);
    this.offset = offset;
    this.problem = problem;
  }

  /// Where in the input the problem is: the offset of the byte that starts
  /// the item, or the byte that is wrong.
  ///
  /// @return the offset, from 0
  public int offset() {
    return offset;
  }

  /// The problem without where it is, such as
  /// `additional information 28 is reserved (major type 0)`.
  ///
  /// @return the problem
  public String problem() {
    return problem;
  }
}
