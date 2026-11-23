package com.snaphop.webauthn;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/// Writes the CBOR the tests need: integers, byte and text strings, lists
/// and maps (in the order given), with the shortest heads.
final class TestCbor {

  private TestCbor() {}

  static byte[] encode(Object value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    write(out, value);
    return out.toByteArray();
  }

  static void write(ByteArrayOutputStream out, Object value) {
    switch (value) {
      case Integer i -> integer(out, i);
      case Long l -> integer(out, l);
      case byte[] b -> {
        head(out, 2, b.length);
        out.writeBytes(b);
      }
      case String s -> {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        head(out, 3, b.length);
        out.writeBytes(b);
      }
      case Raw r -> out.writeBytes(r.bytes());
      case List<?> list -> {
        head(out, 4, list.size());
        for (Object o : list) {
          write(out, o);
        }
      }
      case Map<?, ?> map -> {
        head(out, 5, map.size());
        for (Map.Entry<?, ?> e : map.entrySet()) {
          write(out, e.getKey());
          write(out, e.getValue());
        }
      }
      case Boolean b -> out.write(b ? 0xf5 : 0xf4);
      default -> throw new IllegalArgumentException(value.getClass().getName());
    }
  }

  /// Bytes written as they are: CBOR made some other way.
  static final class Raw {
    private final byte[] bytes;

    Raw(byte[] bytes) {
      this.bytes = bytes.clone();
    }

    byte[] bytes() {
      return bytes.clone();
    }
  }

  private static void integer(ByteArrayOutputStream out, long v) {
    if (v >= 0) {
      head(out, 0, v);
    } else {
      head(out, 1, -1 - v);
    }
  }

  static void head(ByteArrayOutputStream out, int major, long argument) {
    if (argument < 24) {
      out.write((major << 5) | (int) argument);
    } else if (argument < 0x100) {
      out.write((major << 5) | 24);
      out.write((int) argument);
    } else if (argument < 0x10000) {
      out.write((major << 5) | 25);
      out.write((int) (argument >> 8));
      out.write((int) argument & 0xff);
    } else {
      out.write((major << 5) | 26);
      for (int i = 3; i >= 0; i--) {
        out.write((int) (argument >> (8 * i)) & 0xff);
      }
    }
  }
}
