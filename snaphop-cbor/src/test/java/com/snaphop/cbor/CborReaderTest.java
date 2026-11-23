package com.snaphop.cbor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/// What the reader accepts and refuses beyond RFC 8949's examples: validity,
/// the canonical mode, the depth limit, and the values' own rules.
class CborReaderTest {

  enum Sample {
    // Validity: refused in every mode.
    DUPLICATE_KEY("a201000101", Mode.WELL_FORMED, "!Not valid CBOR at byte 3: the key 1 is in the map twice"),
    DUPLICATE_KEY_WRITTEN_TWO_WAYS("a2010018010a", Mode.WELL_FORMED, "!Not valid CBOR at byte 3: the key 1 is in the map twice"),
    DUPLICATE_BYTES_KEY_IN_CHUNKS("a242000000" + "5f41004100ff01", Mode.WELL_FORMED, "!Not valid CBOR at byte 5: the key h'0000' is in the map twice"),
    DUPLICATE_MAP_KEY_REORDERED("a2a2010002000aa2020001000b", Mode.WELL_FORMED, "!Not valid CBOR at byte 7: the key {2: 0, 1: 0} is in the map twice"),
    DUPLICATE_FLOAT_KEY_IN_TWO_WIDTHS("a2f93c0000fa3f80000001", Mode.WELL_FORMED, "!Not valid CBOR at byte 5: the key 1.0 is in the map twice"),
    INT_AND_FLOAT_KEYS_DIFFER("a201f4f93c00f5", Mode.WELL_FORMED, "{1: false, 1.0: true}"),
    TEXT_NOT_UTF8("61ff", Mode.WELL_FORMED, "!Not valid CBOR at byte 0: a text string that is not UTF-8"),
    TEXT_OVERLONG_UTF8("62c0af", Mode.WELL_FORMED, "!Not valid CBOR at byte 0: a text string that is not UTF-8"),
    TEXT_SURROGATE_IN_UTF8("63eda080", Mode.WELL_FORMED, "!Not valid CBOR at byte 0: a text string that is not UTF-8"),
    TEXT_CHARACTER_SPLIT_ACROSS_CHUNKS("7f61c361bcff", Mode.WELL_FORMED, "!Not valid CBOR at byte 1: a text string that is not UTF-8"),
    TEXT_ESCAPED_WHEN_SHOWN("6c0a7465737409c3bc22e6b0b4", Mode.WELL_FORMED, "\"\\ntest\\t\\u00fc\\\"\\u6c34\""),
    TRAILING_BYTE("0000", Mode.WELL_FORMED, "!Not well-formed CBOR at byte 1: 1 byte after the item"),
    TRAILING_BYTES("000000", Mode.WELL_FORMED, "!Not well-formed CBOR at byte 1: 2 bytes after the item"),
    EMPTY("", Mode.WELL_FORMED, "!Not well-formed CBOR at byte 0: the input ends before an item"),
    SIMPLE_32("f820", Mode.WELL_FORMED, "simple(32)"),
    SIMPLE_19("f3", Mode.WELL_FORMED, "simple(19)"),
    LARGEST_TAG("dbffffffffffffffff00", Mode.WELL_FORMED, "18446744073709551615(0)"),
    INDEFINITE_EMPTY_TEXT("7fff", Mode.WELL_FORMED, "\"\""),
    INDEFINITE_EMPTY_MAP("bfff", Mode.WELL_FORMED, "{}"),
    BREAK_AFTER_KEY_IN_DEFINITE_MAP("a101ff", Mode.WELL_FORMED, "!Not well-formed CBOR at byte 2: a break outside an indefinite-length item"),
    HUGE_ARRAY("9b00000000ffffffff00", Mode.WELL_FORMED, "!Not well-formed CBOR at byte 0: an array of 4294967295 items, but only 1 byte is left"),
    HUGE_MAP("bb00000000ffffffff0000", Mode.WELL_FORMED, "!Not well-formed CBOR at byte 0: a map of 4294967295 entries, but only 2 bytes are left"),
    HUGE_CHUNK("5f5affffffff00ff", Mode.WELL_FORMED, "!Not well-formed CBOR at byte 1: a byte string of 4294967295 bytes, but only 2 bytes are left"),
    RESERVED_CHUNK("5f5cff", Mode.WELL_FORMED, "!Not well-formed CBOR at byte 1: additional information 28 is reserved (major type 2)"),

    // The canonical mode.
    CANONICAL_ORDER("a3010041a000616100", Mode.CANONICAL, "{1: 0, h'a0': 0, \"a\": 0}"),
    CANONICAL_INT_IN_TWO_BYTES("1817", Mode.CANONICAL, "!Not canonical CBOR at byte 0: 23 is written in 2 bytes, more than it needs"),
    CANONICAL_INT_IN_THREE_BYTES("1900ff", Mode.CANONICAL, "!Not canonical CBOR at byte 0: 255 is written in 3 bytes, more than it needs"),
    CANONICAL_INT_IN_FIVE_BYTES("1a0000ffff", Mode.CANONICAL, "!Not canonical CBOR at byte 0: 65535 is written in 5 bytes, more than it needs"),
    CANONICAL_INT_IN_NINE_BYTES("1b00000000ffffffff", Mode.CANONICAL, "!Not canonical CBOR at byte 0: 4294967295 is written in 9 bytes, more than it needs"),
    CANONICAL_SMALLEST_IN_EACH_WIDTH("841818190100" + "1a00010000" + "1b0000000100000000", Mode.CANONICAL, "[24, 256, 65536, 4294967296]"),
    CANONICAL_LENGTH("580100", Mode.CANONICAL, "!Not canonical CBOR at byte 0: 1 is written in 2 bytes, more than it needs"),
    CANONICAL_TAG("d8010a", Mode.CANONICAL, "!Not canonical CBOR at byte 0: 1 is written in 2 bytes, more than it needs"),
    CANONICAL_NEGATIVE("3817", Mode.CANONICAL, "!Not canonical CBOR at byte 0: 23 is written in 2 bytes, more than it needs"),
    CANONICAL_INDEFINITE_BYTES("5f4100ff", Mode.CANONICAL, "!Not canonical CBOR at byte 0: an indefinite length"),
    CANONICAL_INDEFINITE_TEXT("7f6161ff", Mode.CANONICAL, "!Not canonical CBOR at byte 0: an indefinite length"),
    CANONICAL_INDEFINITE_ARRAY("9fff", Mode.CANONICAL, "!Not canonical CBOR at byte 0: an indefinite length"),
    CANONICAL_INDEFINITE_MAP("bfff", Mode.CANONICAL, "!Not canonical CBOR at byte 0: an indefinite length"),
    CANONICAL_KEYS_OUT_OF_ORDER("a202000100", Mode.CANONICAL, "!Not canonical CBOR at byte 3: the key 1 is out of order"),
    CANONICAL_LONGER_KEY_FIRST("a26161000100", Mode.CANONICAL, "!Not canonical CBOR at byte 4: the key 1 is out of order"),
    CANONICAL_SAME_LENGTH_BY_BYTES("a220000100", Mode.CANONICAL, "!Not canonical CBOR at byte 3: the key 1 is out of order"),
    CANONICAL_STILL_REFUSES_DUPLICATES("a201000100", Mode.CANONICAL, "!Not valid CBOR at byte 3: the key 1 is in the map twice"),

    // Depth: a container at the limit is refused.
    DEPTH_AT_LIMIT("8180", Mode.DEPTH_TWO, "[[]]"),
    DEPTH_OVER_LIMIT("818180", Mode.DEPTH_TWO, "!CBOR past the reader's limits at byte 2: nested deeper than 2"),
    DEPTH_COUNTS_TAGS("81c180", Mode.DEPTH_TWO, "!CBOR past the reader's limits at byte 2: nested deeper than 2"),
    DEPTH_COUNTS_MAPS("a101a100f6", Mode.DEPTH_TWO, "{1: {0: null}}"),
    DEPTH_COUNTS_MAP_KEYS("a1a10000a1000a", Mode.DEPTH_TWO, "{{0: 0}: {0: 10}}"),
    DEPTH_ZERO_ALLOWS_SCALARS("01", Mode.DEPTH_ZERO, "1"),
    DEPTH_ZERO_REFUSES_CONTAINERS("80", Mode.DEPTH_ZERO, "!CBOR past the reader's limits at byte 0: nested deeper than 0");

    final String hex;
    final Mode mode;
    final String expected;

    Sample(String hex, Mode mode, String expected) {
      this.hex = hex;
      this.mode = mode;
      this.expected = expected;
    }
  }

  enum Mode {
    WELL_FORMED,
    CANONICAL,
    DEPTH_TWO,
    DEPTH_ZERO;

    CborReader reader() {
      return switch (this) {
        case WELL_FORMED -> CborReader.builder().build();
        case CANONICAL -> CborReader.builder().mode(CborReader.Mode.CANONICAL).build();
        case DEPTH_TWO -> CborReader.builder().maxDepth(2).build();
        case DEPTH_ZERO -> CborReader.builder().maxDepth(0).build();
      };
    }
  }

  @ParameterizedTest
  @EnumSource
  void sample(Sample s) {
    byte[] bytes = HexFormat.of().parseHex(s.hex);
    if (s.expected.startsWith("!")) {
      CborParseException e = assertThrows(CborParseException.class, () -> s.mode.reader().read(bytes));
      String message = String.valueOf(e.getMessage());
      assertEquals(s.expected.substring(1), message);
      assertEquals(message, message.substring(0, message.indexOf(" at byte ")) + " at byte " + e.offset() + ": " + e.problem());
    } else {
      assertEquals(s.expected, s.mode.reader().read(bytes).toString());
    }
  }

  @Test
  void canonicalAcceptsWhatItWrites() {
    CborReader canonical = Mode.CANONICAL.reader();
    CborValue value = Mode.WELL_FORMED.reader().read(HexFormat.of().parseHex("bf6161f5a20102000140ff"));
    assertEquals(value, canonical.read(Encoder.canonical(value)));
  }

  @Test
  void readPrefix() {
    byte[] bytes = HexFormat.of().parseHex("ff" + "a10102" + "781a61");
    CborReader.Item item = Mode.WELL_FORMED.reader().readPrefix(bytes, 1);
    assertEquals("{1: 2}", item.value().toString());
    assertEquals(4, item.end());
    CborParseException e = assertThrows(CborParseException.class, () -> Mode.WELL_FORMED.reader().readPrefix(bytes, 4));
    assertEquals("Not well-formed CBOR at byte 4: a text string of 26 bytes, but only 1 byte is left", e.getMessage());
    CborParseException end = assertThrows(CborParseException.class, () -> Mode.WELL_FORMED.reader().readPrefix(bytes, 7));
    assertEquals("Not well-formed CBOR at byte 7: the input ends before an item", end.getMessage());
    assertThrows(IndexOutOfBoundsException.class, () -> Mode.WELL_FORMED.reader().readPrefix(bytes, 8));
    assertThrows(IndexOutOfBoundsException.class, () -> Mode.WELL_FORMED.reader().readPrefix(bytes, -1));
  }

  @Test
  void maxDepthRange() {
    assertEquals("maxDepth must be 0 to 1000: -1",
        assertThrows(IllegalArgumentException.class, () -> CborReader.builder().maxDepth(-1)).getMessage());
    assertEquals("maxDepth must be 0 to 1000: 1001",
        assertThrows(IllegalArgumentException.class, () -> CborReader.builder().maxDepth(1001)).getMessage());
    byte[] deep = new byte[1001];
    java.util.Arrays.fill(deep, 0, 1000, (byte) 0x81);
    CborReader thousand = CborReader.builder().maxDepth(1000).build();
    assertEquals(1000, depth(thousand.read(deep)));
  }

  private static int depth(CborValue v) {
    int d = 0;
    while (v instanceof CborArray a && !a.items().isEmpty()) {
      v = a.items().get(0);
      d++;
    }
    return d;
  }

  @Test
  void values() {
    CborMap map = (CborMap) Mode.WELL_FORMED.reader().read(HexFormat.of().parseHex("a3010203206166f5"));
    assertEquals(CborInteger.of(2), map.getOrNull(1));
    assertEquals(CborInteger.of(-1), map.getOrNull(3));
    assertEquals(CborSimple.TRUE, map.getOrNull("f"));
    assertEquals(CborSimple.TRUE, map.getOrNull(new CborText("f")));
    assertNull(map.getOrNull(2));
    assertNull(map.getOrNull("g"));
    assertEquals(3, map.size());
    CborMap reordered = (CborMap) Mode.WELL_FORMED.reader().read(HexFormat.of().parseHex("a36166f501020320"));
    assertEquals(map, reordered);
    assertEquals(map.hashCode(), reordered.hashCode());
    assertEquals(false, map.equals(Mode.WELL_FORMED.reader().read(HexFormat.of().parseHex("a3010203206166f4"))));
    assertEquals(false, map.equals(Mode.WELL_FORMED.reader().read(HexFormat.of().parseHex("a201020320"))));
    assertEquals(5, map.majorType());
    assertEquals("The key 1 is in the map twice", assertThrows(IllegalArgumentException.class,
        () -> new CborMap(List.of(new CborMap.Entry(CborInteger.of(1), CborSimple.NULL), new CborMap.Entry(CborInteger.of(1), CborSimple.TRUE)))).getMessage());

    byte[] raw = {1, 2, 3};
    CborBytes bytes = CborBytes.of(raw);
    raw[0] = 9;
    byte[] out = bytes.bytes();
    out[1] = 9;
    assertArrayEquals(new byte[] {1, 2, 3}, bytes.bytes());
    assertEquals(3, bytes.length());
    assertEquals(CborBytes.of(new byte[] {1, 2, 3}), bytes);
    assertEquals(CborBytes.of(new byte[] {1, 2, 3}).hashCode(), bytes.hashCode());
    assertEquals(2, bytes.majorType());

    assertEquals(0, CborInteger.of(0).majorType());
    assertEquals(1, CborInteger.of(-1).majorType());
    assertEquals(7, CborInteger.of(7).intValueExact());
    assertEquals(-7L, CborInteger.of(-7).longValueExact());
    assertThrows(ArithmeticException.class, () -> new CborInteger(CborInteger.MAX).longValueExact());
    assertEquals("Outside CBOR's integers (-2^64 to 2^64 - 1): 18446744073709551616",
        assertThrows(IllegalArgumentException.class, () -> new CborInteger(CborInteger.MAX.add(BigInteger.ONE))).getMessage());
    assertEquals("Outside CBOR's integers (-2^64 to 2^64 - 1): -18446744073709551617",
        assertThrows(IllegalArgumentException.class, () -> new CborInteger(CborInteger.MIN.subtract(BigInteger.ONE))).getMessage());

    assertEquals("Not a CBOR simple value: 24", assertThrows(IllegalArgumentException.class, () -> new CborSimple(24)).getMessage());
    assertEquals("Not a CBOR simple value: 31", assertThrows(IllegalArgumentException.class, () -> new CborSimple(31)).getMessage());
    assertEquals("Not a CBOR simple value: 256", assertThrows(IllegalArgumentException.class, () -> new CborSimple(256)).getMessage());
    assertEquals("Not a CBOR simple value: -1", assertThrows(IllegalArgumentException.class, () -> new CborSimple(-1)).getMessage());
    assertEquals("simple(0)", new CborSimple(0).toString());
    assertEquals("simple(32)", new CborSimple(32).toString());
    assertEquals("undefined", CborSimple.UNDEFINED.toString());
    assertEquals(7, CborSimple.NULL.majorType());
    assertEquals(7, new CborFloat(1).majorType());
    assertEquals(3, new CborText("").majorType());
    assertEquals(4, new CborArray(List.of()).majorType());
    assertEquals(6, new CborTag(1, CborSimple.NULL).majorType());
    assertEquals("-1.0e-7", new CborFloat(-1e-7).toString());
    assertEquals("1.0e+21", new CborFloat(1e21).toString());
    assertEquals("123456789012345680000.0", new CborFloat(1.2345678901234568e20).toString());
    assertEquals("0.000001", new CborFloat(1e-6).toString());
    assertEquals(new CborFloat(Double.NaN), new CborFloat(Double.longBitsToDouble(0x7ff0000000000001L)));
    assertEquals(false, new CborFloat(0.0).equals(new CborFloat(-0.0)));
  }
}
