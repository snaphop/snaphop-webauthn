package com.snaphop.cbor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/// RFC 8949's own examples: Appendix A's encodings must read as its
/// diagnostic notation, and Appendix F's must be refused, each with the
/// message in `appendix-f.expected`.
class Rfc8949Test {

  static final Path CORPUS = Path.of("../test/corpus/rfc8949");
  static final CborReader READER = CborReader.builder().build();

  /// Where our diagnostic notation differs from the RFC's, and why.
  static final Map<String, String> DIFFERENT = Map.ofEntries(
      // Bignums are a tag around bytes: the reader does not interpret tags.
      Map.entry("c249010000000000000000", "2(h'010000000000000000')"),
      Map.entry("c349010000000000000000", "3(h'010000000000000000')"),
      // Values, not encodings: chunks and indefinite lengths are not kept.
      Map.entry("5f42010243030405ff", "h'0102030405'"),
      Map.entry("7f657374726561646d696e67ff", "\"streaming\""),
      Map.entry("9fff", "[]"),
      Map.entry("9f018202039f0405ffff", "[1, [2, 3], [4, 5]]"),
      Map.entry("9f01820203820405ff", "[1, [2, 3], [4, 5]]"),
      Map.entry("83018202039f0405ff", "[1, [2, 3], [4, 5]]"),
      Map.entry("83019f0203ff820405", "[1, [2, 3], [4, 5]]"),
      Map.entry("9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff",
          "[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]"),
      Map.entry("bf61610161629f0203ffff", "{\"a\": 1, \"b\": [2, 3]}"),
      Map.entry("826161bf61626163ff", "[\"a\", {\"b\": \"c\"}]"),
      Map.entry("bf6346756ef563416d7421ff", "{\"Fun\": true, \"Amt\": -2}"));

  static Stream<Arguments> appendixA() throws IOException {
    return rows("appendix-a.txt").map(r -> Arguments.of(r[0], r[1]));
  }

  @ParameterizedTest(name = "{0} {1}")
  @MethodSource("appendixA")
  void appendixA(String hex, String rfc) {
    CborValue value = READER.read(HexFormat.of().parseHex(hex));
    String ours = DIFFERENT.get(hex);
    if (ours == null) {
      assertEquals(rfc, value.toString());
    } else {
      assertEquals(ours, value.toString());
      assertNotEquals(rfc, ours);
    }
    // Every example is also read by readPrefix, to its end.
    assertEquals(hex.length() / 2, READER.readPrefix(HexFormat.of().parseHex(hex), 0).end());
  }

  @Test
  void everyDifferenceIsAnExample() throws IOException {
    List<String> hexes = rows("appendix-a.txt").map(r -> r[0]).toList();
    for (String hex : DIFFERENT.keySet()) {
      assertEquals(true, hexes.contains(hex), hex);
    }
  }

  static Stream<Arguments> appendixF() throws IOException {
    List<String[]> examples = rows("appendix-f.txt").toList();
    List<String> expected = Files.readAllLines(Path.of("src/test/resources/appendix-f.expected"), StandardCharsets.UTF_8)
        .stream().filter(l -> !l.startsWith("#")).toList();
    assertEquals(examples.size(), expected.size());
    return Stream.iterate(0, i -> i < examples.size(), i -> i + 1)
        .map(i -> Arguments.of(examples.get(i)[0], examples.get(i)[1], expected.get(i)));
  }

  @ParameterizedTest(name = "{0} {1}")
  @MethodSource("appendixF")
  void appendixF(String hex, String heading, String expected) {
    String[] golden = expected.split("\t", 2);
    assertEquals(hex, golden[0]);
    CborParseException e = assertThrows(CborParseException.class, () -> READER.read(HexFormat.of().parseHex(hex)));
    assertEquals(golden[1], e.getMessage());
  }

  static Stream<String[]> rows(String file) throws IOException {
    return Files.readAllLines(CORPUS.resolve(file), StandardCharsets.UTF_8).stream()
        .filter(l -> !l.startsWith("#") && !l.isBlank())
        .map(l -> l.split("\t", 2));
  }
}
