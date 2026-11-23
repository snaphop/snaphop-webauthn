package com.snaphop.cbor;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/// Reads CBOR (RFC 8949) into [CborValue]s.
///
/// ```java
/// CborReader reader = CborReader.builder().build();
/// CborValue value = reader.read(bytes);
/// ```
///
/// It refuses what is not well-formed, text that is not UTF-8, maps with a
/// key twice, nesting deeper than [Builder#maxDepth(int)], and bytes after
/// the item. A length longer than what is left of the input is refused
/// before anything is allocated, so a few bytes can't ask for gigabytes.
/// Refusals are [CborParseException]s.
public sealed interface CborReader permits DefaultCborReader {

  /// How strict to be about how values are written.
  enum Mode {
    /// Any well-formed, valid CBOR, however it is written: lengths in more
    /// bytes than they need, strings and containers of indefinite length,
    /// map keys in any order.
    WELL_FORMED,
    /// CTAP2's canonical form (as authenticators write CBOR, after RFC 7049
    /// section 3.9): every integer, length and tag in as few bytes as it
    /// needs, no indefinite lengths, and map keys in order (shorter
    /// encodings first, then byte by byte). Also refuses everything
    /// [#WELL_FORMED] refuses.
    CANONICAL
  }

  /// A new builder, set to [Mode#WELL_FORMED] and a depth of 32.
  ///
  /// @return the builder
  static Builder builder() {
    return new Builder();
  }

  /// Reads one item that fills all the bytes.
  ///
  /// @param bytes the CBOR
  /// @return the value
  /// @throws CborParseException if the bytes are refused, including when
  ///     bytes are left after the item
  CborValue read(byte[] bytes);

  /// Reads one item that starts at an offset, and says where it ends:
  /// for an item followed by other data, such as a COSE key inside
  /// WebAuthn's authenticator data.
  ///
  /// @param bytes the input
  /// @param offset where the item starts
  /// @return the value and the offset just past it
  /// @throws CborParseException if the item is refused
  /// @throws IndexOutOfBoundsException if the offset is outside the input
  Item readPrefix(byte[] bytes, int offset);

  /// An item read by [#readPrefix(byte[], int)].
  ///
  /// @param value the value
  /// @param end the offset just past the item
  record Item(CborValue value, int end) {}

  /// Configures a [CborReader].
  final class Builder {

    private Mode mode = Mode.WELL_FORMED;
    private int maxDepth = 32;

    private Builder() {}

    /// How strict to be, [Mode#WELL_FORMED] until set.
    ///
    /// @param mode the mode
    /// @return this builder
    public Builder mode(Mode mode) {
      this.mode = Objects.requireNonNull(mode);
      return this;
    }

    /// How deep arrays, maps and tags may nest: 32 until set. An item that is
    /// not in a container is at depth 0.
    ///
    /// @param maxDepth 0 to 1000
    /// @return this builder
    /// @throws IllegalArgumentException outside 0 to 1000
    public Builder maxDepth(int maxDepth) {
      if (maxDepth < 0 || maxDepth > 1000) {
        throw new IllegalArgumentException("maxDepth must be 0 to 1000: " + maxDepth);
      }
      this.maxDepth = maxDepth;
      return this;
    }

    /// The reader.
    ///
    /// @return the reader
    public CborReader build() {
      return new DefaultCborReader(mode, maxDepth);
    }
  }
}

record DefaultCborReader(CborReader.Mode mode, int maxDepth) implements CborReader {

  @Override
  public CborValue read(byte[] bytes) {
    Decoder d = new Decoder(bytes, 0, this);
    CborValue value = d.item(0);
    if (d.pos != bytes.length) {
      throw d.notWellFormed(d.pos, Decoder.count(bytes.length - d.pos, "byte", "bytes") + " after the item");
    }
    return value;
  }

  @Override
  public Item readPrefix(byte[] bytes, int offset) {
    Objects.checkIndex(offset, bytes.length + 1);
    Decoder d = new Decoder(bytes, offset, this);
    CborValue value = d.item(0);
    return new Item(value, d.pos);
  }
}

final class Decoder {

  private static final int BREAK = 0xff;

  private final byte[] in;
  int pos;
  private final boolean canonical;
  private final int maxDepth;

  Decoder(byte[] in, int pos, DefaultCborReader reader) {
    this.in = in;
    this.pos = pos;
    this.canonical = reader.mode() == CborReader.Mode.CANONICAL;
    this.maxDepth = reader.maxDepth();
  }

  CborValue item(int depth) {
    int start = pos;
    int initial = u8("an item");
    int major = initial >>> 5;
    int info = initial & 0x1f;
    if (info >= 28 && info <= 30) {
      throw notWellFormed(start, "additional information " + info + " is reserved (major type " + major + ")");
    }
    return switch (major) {
      case 0 -> new CborInteger(argument(start, major, info));
      case 1 -> new CborInteger(BigInteger.ONE.negate().subtract(argument(start, major, info)));
      case 2 -> CborBytes.owning(info == 31 ? chunks(start, 2) : take(length(start, major, info)));
      case 3 -> new CborText(utf8(start, info == 31 ? chunks(start, 3) : take(length(start, major, info))));
      case 4 -> array(start, info, depth);
      case 5 -> map(start, info, depth);
      case 6 -> tag(start, info, depth);
      default -> simpleOrFloat(start, info);
    };
  }

  private BigInteger argument(int start, int major, int info) {
    if (info == 31) {
      throw notWellFormed(start, "major type " + major + " cannot have an indefinite length");
    }
    return BigInteger.valueOf(argumentLong(start, info)).and(CborInteger.MAX);
  }

  /// The argument as a long whose 64 bits are unsigned.
  private long argumentLong(int start, int info) {
    if (info < 24) {
      return info;
    }
    int size = 1 << (info - 24);
    long value = 0;
    for (int i = 0; i < size; i++) {
      value = (value << 8) | u8("the argument");
    }
    if (canonical) {
      long smallest = switch (size) {
        case 1 -> 24;
        case 2 -> 0x100;
        case 4 -> 0x10000;
        default -> 0x1_0000_0000L;
      };
      if (Long.compareUnsigned(value, smallest) < 0) {
        throw notCanonical(start, Long.toUnsignedString(value) + " is written in " + (size + 1) + " bytes, more than it needs");
      }
    }
    return value;
  }

  /// A definite length, refused when longer than what is left.
  private int length(int start, int major, int info) {
    long length = argumentLong(start, info);
    long left = (long) in.length - pos;
    if (Long.compareUnsigned(length, left) > 0) {
      throw notWellFormed(start, what(major) + " of " + unsignedCount(length, major) + ", but only " + count(left, "byte is", "bytes are") + " left");
    }
    return (int) length;
  }

  private static String what(int major) {
    return switch (major) {
      case 2 -> "a byte string";
      case 3 -> "a text string";
      case 4 -> "an array";
      default -> "a map";
    };
  }

  private static String unsignedCount(long n, int major) {
    String number = Long.toUnsignedString(n);
    boolean one = n == 1;
    return number + " " + switch (major) {
      case 2, 3 -> one ? "byte" : "bytes";
      case 4 -> one ? "item" : "items";
      default -> one ? "entry" : "entries";
    };
  }

  static String count(long n, String one, String many) {
    return n + " " + (n == 1 ? one : many);
  }

  /// Bytes already known to be there: [#length] checked.
  private byte[] take(int length) {
    byte[] b = Arrays.copyOfRange(in, pos, pos + length);
    pos += length;
    return b;
  }

  /// An indefinite-length string: definite chunks of the same major type until a break.
  private byte[] chunks(int start, int major) {
    if (canonical) {
      throw notCanonical(start, "an indefinite length");
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    while (true) {
      int chunkStart = pos;
      int initial = u8("a chunk or a break");
      if (initial == BREAK) {
        return out.toByteArray();
      }
      int chunkMajor = initial >>> 5;
      int info = initial & 0x1f;
      if (chunkMajor != major) {
        throw notWellFormed(chunkStart, "a chunk of major type " + chunkMajor + " inside an indefinite-length " + (major == 2 ? "byte" : "text") + " string");
      }
      if (info == 31) {
        throw notWellFormed(chunkStart, "an indefinite-length chunk inside an indefinite-length string");
      }
      if (info >= 28) {
        throw notWellFormed(chunkStart, "additional information " + info + " is reserved (major type " + major + ")");
      }
      byte[] chunk = take(length(chunkStart, major, info));
      if (major == 3) {
        utf8(chunkStart, chunk);
      }
      out.writeBytes(chunk);
    }
  }

  private String utf8(int start, byte[] bytes) {
    try {
      return StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes))
          .toString();
    } catch (CharacterCodingException e) {
      throw notValid(start, "a text string that is not UTF-8");
    }
  }

  private CborArray array(int start, int info, int depth) {
    checkDepth(start, depth);
    List<CborValue> items = new ArrayList<>();
    if (info == 31) {
      if (canonical) {
        throw notCanonical(start, "an indefinite length");
      }
      while (!atBreak()) {
        items.add(item(depth + 1));
      }
      pos++;
    } else {
      int count = length(start, 4, info);
      for (int i = 0; i < count; i++) {
        items.add(item(depth + 1));
      }
    }
    return new CborArray(items);
  }

  private CborMap map(int start, int info, int depth) {
    checkDepth(start, depth);
    List<CborMap.Entry> entries = new ArrayList<>();
    Set<CborValue> keys = new HashSet<>();
    int previousKeyStart = -1;
    int previousKeyEnd = -1;
    boolean indefinite = info == 31;
    int count = 0;
    if (indefinite) {
      if (canonical) {
        throw notCanonical(start, "an indefinite length");
      }
    } else {
      // Each entry is at least two bytes.
      long n = argumentLong(start, info);
      long left = (long) in.length - pos;
      if (Long.compareUnsigned(n, left / 2) > 0) {
        throw notWellFormed(start, "a map of " + unsignedCount(n, 5) + ", but only " + count(left, "byte is", "bytes are") + " left");
      }
      count = (int) n;
    }
    for (int i = 0; indefinite ? !atBreak() : i < count; i++) {
      int keyStart = pos;
      CborValue key = item(depth + 1);
      int keyEnd = pos;
      if (indefinite && atBreak()) {
        throw notWellFormed(pos, "a break between a map key and its value");
      }
      CborValue value = item(depth + 1);
      if (!keys.add(key)) {
        throw notValid(keyStart, "the key " + key + " is in the map twice");
      }
      if (canonical && previousKeyStart >= 0 && compareKeys(previousKeyStart, previousKeyEnd, keyStart, keyEnd) > 0) {
        throw notCanonical(keyStart, "the key " + key + " is out of order");
      }
      previousKeyStart = keyStart;
      previousKeyEnd = keyEnd;
      entries.add(new CborMap.Entry(key, value));
    }
    if (indefinite) {
      pos++;
    }
    return new CborMap(entries);
  }

  /// CTAP2's order: shorter encodings first, then byte by byte.
  private int compareKeys(int aStart, int aEnd, int bStart, int bEnd) {
    int byLength = Integer.compare(aEnd - aStart, bEnd - bStart);
    if (byLength != 0) {
      return byLength;
    }
    return Arrays.compareUnsigned(in, aStart, aEnd, in, bStart, bEnd);
  }

  private CborTag tag(int start, int info, int depth) {
    if (info == 31) {
      throw notWellFormed(start, "major type 6 cannot have an indefinite length");
    }
    long number = argumentLong(start, info);
    checkDepth(start, depth);
    return new CborTag(number, item(depth + 1));
  }

  private CborValue simpleOrFloat(int start, int info) {
    if (info < 24) {
      return new CborSimple(info);
    }
    return switch (info) {
      case 24 -> {
        int value = u8("a simple value");
        if (value < 32) {
          throw notWellFormed(start, "simple value " + value + " written in two bytes");
        }
        yield new CborSimple(value);
      }
      case 25 -> new CborFloat(Float.float16ToFloat((short) bits(2)));
      case 26 -> new CborFloat(Float.intBitsToFloat((int) bits(4)));
      case 27 -> new CborFloat(Double.longBitsToDouble(bits(8)));
      default -> throw notWellFormed(start, "a break outside an indefinite-length item");
    };
  }

  private long bits(int size) {
    long value = 0;
    for (int i = 0; i < size; i++) {
      value = (value << 8) | u8("a float");
    }
    return value;
  }

  private boolean atBreak() {
    if (pos >= in.length) {
      throw notWellFormed(pos, "the input ends before a break");
    }
    return (in[pos] & 0xff) == BREAK;
  }

  private void checkDepth(int start, int depth) {
    if (depth >= maxDepth) {
      throw new CborParseException(start, "CBOR past the reader's limits", "nested deeper than " + maxDepth);
    }
  }

  private int u8(String what) {
    if (pos >= in.length) {
      throw notWellFormed(pos, "the input ends before " + what);
    }
    return in[pos++] & 0xff;
  }

  CborParseException notWellFormed(int offset, String problem) {
    return new CborParseException(offset, "Not well-formed CBOR", problem);
  }

  private static CborParseException notValid(int offset, String problem) {
    return new CborParseException(offset, "Not valid CBOR", problem);
  }

  private static CborParseException notCanonical(int offset, String problem) {
    return new CborParseException(offset, "Not canonical CBOR", problem);
  }
}
