package com.snaphop.cbor.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.snaphop.cbor.CborArray;
import com.snaphop.cbor.CborBytes;
import com.snaphop.cbor.CborFloat;
import com.snaphop.cbor.CborInteger;
import com.snaphop.cbor.CborMap;
import com.snaphop.cbor.CborParseException;
import com.snaphop.cbor.CborReader;
import com.snaphop.cbor.CborSimple;
import com.snaphop.cbor.CborTag;
import com.snaphop.cbor.CborText;
import com.snaphop.cbor.CborValue;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

/// The same bytes read by this library and by PeterO's CBOR (which Yubico's
/// WebAuthn library uses) and Jackson's: RFC 8949's examples, random
/// values written every legal way, and those damaged.
///
/// PeterO is the oracle for values and verdicts. Its one difference by
/// design: it checks the content of tags it knows (a bignum's bytes, a
/// date's text), and this reader does not interpret tags. So where only
/// tags explain a difference, it is allowed and counted. Jackson is
/// lenient (it keeps the last of a key written twice), so its verdicts are
/// only counted, never asserted.
class CborOracleTest {

  static final CborReader READER = CborReader.builder().build();
  static final CBORMapper JACKSON = new CBORMapper();
  static final int ITERATIONS = Integer.getInteger("fuzz.iterations", 3000);

  @Test
  void rfcExamples() throws IOException {
    for (String file : List.of("appendix-a.txt", "appendix-f.txt")) {
      for (String line : Files.readAllLines(Path.of("../corpus/rfc8949").resolve(file), StandardCharsets.UTF_8)) {
        if (line.startsWith("#") || line.isBlank()) {
          continue;
        }
        byte[] bytes = HexFormat.of().parseHex(line.substring(0, line.indexOf('\t')));
        CborValue ours = oursOrNull(bytes);
        CBORObject peterO = peterOOrNull(bytes);
        assertEquals(peterO != null, ours != null, line);
        if (ours != null && peterO != null && !line.startsWith("c2") && !line.startsWith("c3")) {
          // Bignums (tags 2 and 3) PeterO reads as integers; this reader keeps the tag.
          assertEquals(ours, convert(peterO), line);
        }
      }
    }
  }

  @Test
  void randomValuesEveryLegalWay() {
    Random random = new Random(1);
    int tagged = 0;
    for (int i = 0; i < ITERATIONS; i++) {
      CborValue value = Encoder.randomValue(random, 4);
      byte[] bytes = Encoder.any(random).encode(value);
      CborValue ours = READER.read(bytes);
      assertEquals(value, ours);
      CBORObject peterO = peterOOrNull(bytes);
      if (peterO == null || !ours.equals(convert(peterO))) {
        // Only tags may explain it.
        assertEquals(true, hasTag(value), () -> "PeterO differs without a tag: " + HexFormat.of().formatHex(bytes));
        tagged++;
      }
    }
    System.out.println("Random values PeterO read differently, all for tags: " + tagged + " of " + ITERATIONS);
  }

  @Test
  void damaged() {
    Random random = new Random(2);
    Map<String, Integer> peterO = new TreeMap<>();
    Map<String, Integer> jackson = new TreeMap<>();
    for (int i = 0; i < ITERATIONS * 3; i++) {
      CborValue value = Encoder.randomValue(random, 4);
      byte[] bytes = damage(random, Encoder.any(random).encode(value));
      CborValue ours = oursOrNull(bytes);
      CBORObject theirs = peterOOrNull(bytes);
      String verdict = (ours != null ? "A" : "R") + (theirs != null ? "A" : "R");
      if (ours != null && theirs == null) {
        // Accepted by us alone: only tag content can explain it.
        assertEquals(true, hasTag(ours), () -> "Accepted by us, refused by PeterO, no tag: " + HexFormat.of().formatHex(bytes));
        verdict += " (a tag)";
      } else if (ours == null && theirs != null) {
        // Refused by us alone: say what we refused.
        verdict += " (" + whyRefused(bytes) + ")";
      } else if (ours != null && theirs != null && !ours.equals(convert(theirs))) {
        assertEquals(true, hasTag(ours), () -> "Read differently, no tag: " + HexFormat.of().formatHex(bytes));
        verdict += " (read differently: a tag)";
      }
      peterO.merge(verdict, 1, Integer::sum);
      jackson.merge((ours != null ? "A" : "R") + (jacksonAccepts(bytes) ? "A" : "R"), 1, Integer::sum);
    }
    System.out.println("Damaged CBOR, ours and PeterO: " + peterO);
    System.out.println("Damaged CBOR, ours and Jackson: " + jackson);
  }

  static String whyRefused(byte[] bytes) {
    try {
      READER.read(bytes);
      return "?";
    } catch (CborParseException e) {
      String p = e.problem();
      return p.replaceAll("[0-9]+", "N").replaceAll("\"[^\"]*\"|h'[^']*'|\\{.*\\}|\\[.*\\]", "X");
    }
  }

  static @Nullable CborValue oursOrNull(byte[] bytes) {
    try {
      return READER.read(bytes);
    } catch (CborParseException e) {
      return null;
    }
  }

  static @Nullable CBORObject peterOOrNull(byte[] bytes) {
    try {
      return CBORObject.DecodeFromBytes(bytes);
    } catch (RuntimeException e) {
      return null;
    }
  }

  static boolean jacksonAccepts(byte[] bytes) {
    try {
      JACKSON.readTree(bytes);
      return true;
    } catch (IOException | RuntimeException e) {
      return false;
    }
  }

  static boolean hasTag(CborValue v) {
    return switch (v) {
      case CborTag t -> true;
      case CborArray a -> a.items().stream().anyMatch(CborOracleTest::hasTag);
      case CborMap m -> m.entries().stream().anyMatch(e -> hasTag(e.key()) || hasTag(e.value()));
      default -> false;
    };
  }

  /// PeterO's object as this library's value.
  static CborValue convert(CBORObject o) {
    if (o.isTagged()) {
      return new CborTag(new BigInteger(o.getMostOuterTag().toString()).longValue(), convert(o.UntagOne()));
    }
    CBORType type = o.getType();
    if (type == CBORType.Integer) {
      return new CborInteger(new BigInteger(o.AsEIntegerValue().toString()));
    } else if (type == CBORType.FloatingPoint) {
      return new CborFloat(o.AsDoubleValue());
    } else if (type == CBORType.ByteString) {
      return CborBytes.of(o.GetByteString());
    } else if (type == CBORType.TextString) {
      return new CborText(o.AsString());
    } else if (type == CBORType.Array) {
      List<CborValue> items = new ArrayList<>();
      for (CBORObject item : o.getValues()) {
        items.add(convert(item));
      }
      return new CborArray(items);
    } else if (type == CBORType.Map) {
      List<CborMap.Entry> entries = new ArrayList<>();
      for (Map.Entry<CBORObject, CBORObject> e : o.getEntries()) {
        entries.add(new CborMap.Entry(convert(e.getKey()), convert(e.getValue())));
      }
      return new CborMap(entries);
    } else if (type == CBORType.Boolean) {
      return o.isTrue() ? CborSimple.TRUE : CborSimple.FALSE;
    } else if (o.isNull()) {
      return CborSimple.NULL;
    } else if (o.isUndefined()) {
      return CborSimple.UNDEFINED;
    }
    return new CborSimple(o.getSimpleValue());
  }

  static byte[] damage(Random random, byte[] bytes) {
    if (bytes.length == 0) {
      return new byte[] {(byte) random.nextInt(256)};
    }
    byte[] out = bytes.clone();
    switch (random.nextInt(5)) {
      case 0 -> out[random.nextInt(out.length)] ^= (byte) (1 << random.nextInt(8));
      case 1 -> out[random.nextInt(out.length)] = (byte) random.nextInt(256);
      case 2 -> out = java.util.Arrays.copyOf(out, random.nextInt(out.length));
      case 3 -> {
        int at = random.nextInt(out.length + 1);
        byte[] longer = new byte[out.length + 1];
        System.arraycopy(out, 0, longer, 0, at);
        longer[at] = (byte) random.nextInt(256);
        System.arraycopy(out, at, longer, at + 1, out.length - at);
        out = longer;
      }
      default -> {
        int at = random.nextInt(out.length);
        byte[] shorter = new byte[out.length - 1];
        System.arraycopy(out, 0, shorter, 0, at);
        System.arraycopy(out, at + 1, shorter, at, out.length - at - 1);
        out = shorter;
      }
    }
    return out;
  }
}
