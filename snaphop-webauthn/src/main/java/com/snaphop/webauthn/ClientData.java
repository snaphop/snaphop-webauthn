package com.snaphop.webauthn;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/// The client data (`clientDataJSON`): what the browser says it was asked,
/// read strictly. It must be UTF-8 JSON (RFC 8259) whose top is an object,
/// with no member twice at any depth (two `origin`s could be read
/// differently by two parsers), `type`, `challenge` and `origin` as strings,
/// `crossOrigin` as a boolean and `topOrigin` as a string when present.
/// Other members (`extraData`, `tokenBinding`, members of the future) are
/// read and ignored.
record ClientData(String type, String challenge, String origin, boolean crossOrigin, @Nullable String topOrigin) {

  /// Larger client data than any browser sends; refused before reading.
  static final int MAX_BYTES = 64 * 1024;

  static ClientData read(byte[] json) {
    if (json.length > MAX_BYTES) {
      throw refuse("The client data is " + json.length + " bytes, more than " + MAX_BYTES);
    }
    Object top = json(json);
    if (!(top instanceof Map<?, ?> map)) {
      throw refuse("The client data is not a JSON object");
    }
    String type = string(map, "type");
    String challenge = string(map, "challenge");
    String origin = string(map, "origin");
    Object cross = map.get("crossOrigin");
    if (cross != null && !(cross instanceof Boolean)) {
      throw refuse("The client data's \"crossOrigin\" is not true or false");
    }
    @Nullable String topOrigin = map.containsKey("topOrigin") ? string(map, "topOrigin") : null;
    return new ClientData(type, challenge, origin, Boolean.TRUE.equals(cross), topOrigin);
  }

  /// Any JSON document, as UTF-8 bytes.
  static Object json(byte[] json) {
    String text;
    try {
      text = StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(json))
          .toString();
    } catch (CharacterCodingException e) {
      throw refuse("The client data is not UTF-8");
    }
    // WebAuthn uses the Encoding Standard's UTF-8 decode, which strips one BOM.
    return new Json(text.startsWith("\uFEFF") ? text.substring(1) : text).document();
  }

  private static String string(Map<?, ?> map, String name) {
    Object v = map.get(name);
    if (v instanceof String s) {
      return s;
    }
    if (v == null && !map.containsKey(name)) {
      throw refuse("The client data has no \"" + name + "\"");
    }
    throw refuse("The client data's \"" + name + "\" is not a string");
  }

  static WebauthnException refuse(String message) {
    return new WebauthnException(WebauthnException.Reason.CLIENT_DATA, message);
  }

  /// A strict JSON (RFC 8259) reader: objects as maps in order, arrays as
  /// lists, `null` as a marker. Numbers are checked against JSON's grammar
  /// and kept as their text, never converted: nothing in the client data is
  /// a number, and converting `1e999999999` is how parsers get hurt. Refuses
  /// a member twice, nesting deeper than 32, and anything after the value.
  static final class Json {

    static final Object NULL = new Object();

    /// A number, as written.
    record JsonNumber(String text) {}
    private static final int MAX_DEPTH = 32;

    private final String in;
    private int pos;

    Json(String in) {
      this.in = in;
    }

    Object document() {
      Object value = value(0);
      skipSpace();
      if (pos != in.length()) {
        throw error("text after the JSON value");
      }
      return value;
    }

    private Object value(int depth) {
      skipSpace();
      if (pos >= in.length()) {
        throw error("the JSON ends before a value");
      }
      char c = in.charAt(pos);
      return switch (c) {
        case '{' -> object(depth);
        case '[' -> array(depth);
        case '"' -> string();
        case 't' -> literal("true", true);
        case 'f' -> literal("false", false);
        case 'n' -> literal("null", NULL);
        default -> {
          if (c == '-' || (c >= '0' && c <= '9')) {
            yield number();
          }
          throw error("unexpected " + describe(c));
        }
      };
    }

    private Map<String, Object> object(int depth) {
      if (depth >= MAX_DEPTH) {
        throw error("JSON nested deeper than " + MAX_DEPTH);
      }
      pos++;
      Map<String, Object> map = new LinkedHashMap<>();
      skipSpace();
      if (peek() == '}') {
        pos++;
        return map;
      }
      while (true) {
        skipSpace();
        if (peek() != '"') {
          throw error("expected a member name");
        }
        int at = pos;
        String name = string();
        skipSpace();
        expect(':');
        Object value = value(depth + 1);
        if (map.putIfAbsent(name, value) != null) {
          pos = at;
          throw error("the member \"" + name + "\" is there twice");
        }
        skipSpace();
        char c = peek();
        pos++;
        if (c == '}') {
          return map;
        }
        if (c != ',') {
          pos--;
          throw error("expected , or }");
        }
      }
    }

    private List<Object> array(int depth) {
      if (depth >= MAX_DEPTH) {
        throw error("JSON nested deeper than " + MAX_DEPTH);
      }
      pos++;
      List<Object> list = new ArrayList<>();
      skipSpace();
      if (peek() == ']') {
        pos++;
        return list;
      }
      while (true) {
        list.add(value(depth + 1));
        skipSpace();
        char c = peek();
        pos++;
        if (c == ']') {
          return list;
        }
        if (c != ',') {
          pos--;
          throw error("expected , or ]");
        }
      }
    }

    private String string() {
      pos++;
      StringBuilder b = new StringBuilder();
      while (true) {
        if (pos >= in.length()) {
          throw error("the JSON ends inside a string");
        }
        char c = in.charAt(pos++);
        if (c == '"') {
          return b.toString();
        }
        if (c < 0x20) {
          pos--;
          throw error("a control character in a string");
        }
        if (c != '\\') {
          b.append(c);
          continue;
        }
        if (pos >= in.length()) {
          throw error("the JSON ends inside a string");
        }
        char e = in.charAt(pos++);
        switch (e) {
          case '"', '\\', '/' -> b.append(e);
          case 'b' -> b.append('\b');
          case 'f' -> b.append('\f');
          case 'n' -> b.append('\n');
          case 'r' -> b.append('\r');
          case 't' -> b.append('\t');
          case 'u' -> {
            if (pos + 4 > in.length()) {
              throw error("the JSON ends inside a \\u escape");
            }
            int cp = 0;
            for (int i = 0; i < 4; i++) {
              char digit = in.charAt(pos + i);
              if (!HexFormat.isHexDigit(digit)) {
                throw error("a \\u escape that is not four hex digits");
              }
              cp = cp * 16 + HexFormat.fromHexDigit(digit);
            }
            pos += 4;
            b.append((char) cp);
          }
          default -> {
            pos -= 2;
            throw error("an unknown escape \\" + e);
          }
        }
      }
    }

    private Object number() {
      int start = pos;
      if (peek() == '-') {
        pos++;
      }
      if (peek() == '0') {
        pos++;
      } else if (isDigit(peek())) {
        while (isDigit(peek())) {
          pos++;
        }
      } else {
        throw error("a number without digits");
      }
      if (peek() == '.') {
        pos++;
        if (!isDigit(peek())) {
          throw error("a number without digits after the point");
        }
        while (isDigit(peek())) {
          pos++;
        }
      }
      if (peek() == 'e' || peek() == 'E') {
        pos++;
        if (peek() == '+' || peek() == '-') {
          pos++;
        }
        if (!isDigit(peek())) {
          throw error("a number without digits in its exponent");
        }
        while (isDigit(peek())) {
          pos++;
        }
      }
      return new JsonNumber(in.substring(start, pos));
    }

    private Object literal(String word, Object value) {
      if (!in.startsWith(word, pos)) {
        throw error("unexpected " + describe(in.charAt(pos)));
      }
      pos += word.length();
      return value;
    }

    private void expect(char c) {
      if (peek() != c) {
        throw error("expected " + c);
      }
      pos++;
    }

    private char peek() {
      return pos < in.length() ? in.charAt(pos) : '\0';
    }

    private static boolean isDigit(char c) {
      return c >= '0' && c <= '9';
    }

    private void skipSpace() {
      while (pos < in.length()) {
        char c = in.charAt(pos);
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
          return;
        }
        pos++;
      }
    }

    private static String describe(char c) {
      return c >= 0x20 && c < 0x7f ? "'" + c + "'" : String.format("U+%04X", (int) c);
    }

    private WebauthnException error(String problem) {
      return refuse("The client data is not JSON at character " + pos + ": " + problem);
    }
  }
}
