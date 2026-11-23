package com.snaphop.webauthn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/// The client data's JSON reader against JSONTestSuite: `y_` must be read
/// and `n_` refused, with [WebauthnException] and nothing else; `i_` may go
/// either way, with nothing else.
class JsonTestSuiteTest {

  static final Path SUITE = Path.of("../test/corpus/jsontestsuite");

  /// Valid JSON we refuse on purpose, and why.
  static final Map<String, String> STRICTER = Map.of(
      "y_object_duplicated_key.json", "a member twice could be read differently by two parsers",
      "y_object_duplicated_key_and_value.json", "a member twice could be read differently by two parsers");

  @Test
  void unicodeEscapeRequiresAsciiHex() {
    byte[] document = "\"\\u００４１\"".getBytes(StandardCharsets.UTF_8);
    WebauthnException error = assertThrows(WebauthnException.class, () -> ClientData.json(document));
    assertEquals("The client data is not JSON at character 3: a \\u escape that is not four hex digits", error.getMessage());
  }

  @TestFactory
  Stream<DynamicTest> cases() throws IOException {
    List<Path> files;
    try (var list = Files.list(SUITE)) {
      files = list.filter(p -> p.toString().endsWith(".json")).sorted().toList();
    }
    assertEquals(318, files.size());
    return files.stream().map(p -> DynamicTest.dynamicTest(p.getFileName().toString(), () -> {
      String name = p.getFileName().toString();
      byte[] bytes = Files.readAllBytes(p);
      if (name.startsWith("y_") && !STRICTER.containsKey(name)) {
        ClientData.json(bytes);
      } else if (name.startsWith("n_") || STRICTER.containsKey(name)) {
        assertEquals(WebauthnException.Reason.CLIENT_DATA, assertThrows(WebauthnException.class, () -> ClientData.json(bytes)).reason());
      } else {
        try {
          ClientData.json(bytes);
        } catch (WebauthnException e) {
          assertEquals(WebauthnException.Reason.CLIENT_DATA, e.reason());
        }
      }
    }));
  }
}
