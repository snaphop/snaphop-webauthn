package com.snaphop.cbor;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

/// Writes CBOR for the tests: canonically, or in any of the other legal ways
/// (longer heads, indefinite lengths in chunks, floats in more bits, map keys
/// out of order), and makes random values to write.
final class Encoder {

  private final Random random;
  private final boolean canonical;
  /// Whether anything written so far is not canonical.
  boolean wroteNonCanonical;

  private Encoder(Random random, boolean canonical) {
    this.random = random;
    this.canonical = canonical;
  }

  static byte[] canonical(CborValue value) {
    Encoder e = new Encoder(new Random(0), true);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    e.write(out, value);
    return out.toByteArray();
  }

  /// Writes the value in one of its legal encodings, chosen at random.
  static Encoder any(Random random) {
    return new Encoder(random, false);
  }

  byte[] encode(CborValue value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    write(out, value);
    return out.toByteArray();
  }

  private boolean chance(int percent) {
    return !canonical && random.nextInt(100) < percent;
  }

  void write(ByteArrayOutputStream out, CborValue value) {
    switch (value) {
      case CborInteger i -> {
        BigInteger v = i.value();
        if (v.signum() >= 0) {
          head(out, 0, v.longValue());
        } else {
          head(out, 1, BigInteger.ONE.negate().subtract(v).longValue());
        }
      }
      case CborBytes b -> string(out, 2, b.bytes());
      case CborText t -> string(out, 3, t.value().getBytes(StandardCharsets.UTF_8));
      case CborArray a -> {
        boolean indefinite = chance(15);
        if (indefinite) {
          wroteNonCanonical = true;
          out.write(0x9f);
        } else {
          head(out, 4, a.items().size());
        }
        for (CborValue item : a.items()) {
          write(out, item);
        }
        if (indefinite) {
          out.write(0xff);
        }
      }
      case CborMap m -> {
        List<byte[][]> entries = new ArrayList<>();
        for (CborMap.Entry e : m.entries()) {
          entries.add(new byte[][] {encodeNested(e.key()), encodeNested(e.value())});
        }
        List<byte[][]> sorted = new ArrayList<>(entries);
        sorted.sort((x, y) -> x[0].length != y[0].length ? Integer.compare(x[0].length, y[0].length) : Arrays.compareUnsigned(x[0], y[0]));
        if (chance(30)) {
          java.util.Collections.shuffle(entries, random);
        } else {
          entries = sorted;
        }
        for (int k = 0; k < entries.size(); k++) {
          if (!Arrays.equals(entries.get(k)[0], sorted.get(k)[0])) {
            wroteNonCanonical = true;
          }
        }
        boolean indefinite = chance(15);
        if (indefinite) {
          wroteNonCanonical = true;
          out.write(0xbf);
        } else {
          head(out, 5, entries.size());
        }
        for (byte[][] e : entries) {
          out.writeBytes(e[0]);
          out.writeBytes(e[1]);
        }
        if (indefinite) {
          out.write(0xff);
        }
      }
      case CborTag t -> {
        head(out, 6, t.number());
        write(out, t.content());
      }
      case CborSimple s -> {
        if (s.value() < 24) {
          out.write(0xe0 | s.value());
        } else {
          out.write(0xf8);
          out.write(s.value());
        }
      }
      case CborFloat f -> floating(out, f.value());
    }
  }

  private byte[] encodeNested(CborValue v) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    write(out, v);
    return out.toByteArray();
  }

  private void string(ByteArrayOutputStream out, int major, byte[] bytes) {
    if (chance(15)) {
      wroteNonCanonical = true;
      out.write((major << 5) | 31);
      int at = 0;
      while (at < bytes.length) {
        int n = 1 + random.nextInt(Math.max(1, bytes.length - at));
        // Text chunks must each be UTF-8: split only between characters.
        while (major == 3 && at + n < bytes.length && (bytes[at + n] & 0xc0) == 0x80) {
          n++;
        }
        head(out, major, n);
        out.write(bytes, at, n);
        at += n;
      }
      if (chance(30)) {
        head(out, major, 0);
      }
      out.write(0xff);
      return;
    }
    head(out, major, bytes.length);
    out.writeBytes(bytes);
  }

  /// A head with the argument in as few bytes as it needs, or sometimes more.
  void head(ByteArrayOutputStream out, int major, long argument) {
    int smallest;
    if (Long.compareUnsigned(argument, 24) < 0) {
      smallest = 0;
    } else if (Long.compareUnsigned(argument, 0x100) < 0) {
      smallest = 1;
    } else if (Long.compareUnsigned(argument, 0x10000) < 0) {
      smallest = 2;
    } else if (Long.compareUnsigned(argument, 0x1_0000_0000L) < 0) {
      smallest = 3;
    } else {
      smallest = 4;
    }
    int width = smallest;
    if (chance(15) && smallest < 4) {
      width = smallest + 1 + random.nextInt(4 - smallest);
      wroteNonCanonical = true;
    }
    if (width == 0) {
      out.write((major << 5) | (int) argument);
      return;
    }
    out.write((major << 5) | (23 + width));
    int bytes = 1 << (width - 1);
    for (int i = bytes - 1; i >= 0; i--) {
      out.write((int) (argument >>> (8 * i)) & 0xff);
    }
  }

  private void floating(ByteArrayOutputStream out, double v) {
    float f = (float) v;
    boolean fitsFloat = Double.isNaN(v) || (double) f == v;
    short half = Float.floatToFloat16(f);
    boolean fitsHalf = fitsFloat && (Double.isNaN(v) || (double) Float.float16ToFloat(half) == v);
    int choice;
    if (fitsHalf) {
      choice = canonical ? 2 : new int[] {2, 4, 8}[random.nextInt(3)];
    } else if (fitsFloat) {
      choice = canonical ? 4 : new int[] {4, 8}[random.nextInt(2)];
    } else {
      choice = 8;
    }
    switch (choice) {
      case 2 -> {
        out.write(0xf9);
        out.write((half >> 8) & 0xff);
        out.write(half & 0xff);
      }
      case 4 -> {
        out.write(0xfa);
        int bits = Float.floatToIntBits(f);
        for (int i = 3; i >= 0; i--) {
          out.write((bits >>> (8 * i)) & 0xff);
        }
      }
      default -> {
        out.write(0xfb);
        long bits = Double.doubleToLongBits(v);
        for (int i = 7; i >= 0; i--) {
          out.write((int) (bits >>> (8 * i)) & 0xff);
        }
      }
    }
  }

  /// A random value, at most `depth` containers deep.
  static CborValue randomValue(Random r, int depth) {
    int kind = r.nextInt(depth > 0 ? 9 : 6);
    return switch (kind) {
      case 0 -> new CborInteger(randomInteger(r));
      case 1 -> CborBytes.of(randomBytes(r));
      case 2 -> new CborText(randomText(r));
      case 3 -> randomSimple(r);
      case 4 -> new CborFloat(randomDouble(r));
      case 5 -> new CborInteger(BigInteger.valueOf(r.nextInt(48) - 24));
      case 6 -> {
        List<CborValue> items = new ArrayList<>();
        int n = r.nextInt(6);
        for (int i = 0; i < n; i++) {
          items.add(randomValue(r, depth - 1));
        }
        yield new CborArray(items);
      }
      case 7 -> {
        List<CborMap.Entry> entries = new ArrayList<>();
        Set<CborValue> keys = new HashSet<>();
        int n = r.nextInt(6);
        for (int i = 0; i < n; i++) {
          CborValue key = randomValue(r, depth - 1);
          if (keys.add(key)) {
            entries.add(new CborMap.Entry(key, randomValue(r, depth - 1)));
          }
        }
        yield new CborMap(entries);
      }
      default -> new CborTag(r.nextInt(4) == 0 ? r.nextLong() : r.nextInt(300), randomValue(r, depth - 1));
    };
  }

  private static BigInteger randomInteger(Random r) {
    return switch (r.nextInt(6)) {
      case 0 -> CborInteger.MAX;
      case 1 -> CborInteger.MIN;
      case 2 -> BigInteger.valueOf(r.nextLong()).and(CborInteger.MAX);
      case 3 -> BigInteger.ONE.negate().subtract(BigInteger.valueOf(r.nextLong()).and(CborInteger.MAX));
      default -> BigInteger.valueOf(r.nextInt(70000) - 35000);
    };
  }

  private static byte[] randomBytes(Random r) {
    byte[] b = new byte[r.nextInt(r.nextInt(10) == 0 ? 400 : 12)];
    r.nextBytes(b);
    return b;
  }

  private static String randomText(Random r) {
    StringBuilder b = new StringBuilder();
    int n = r.nextInt(10);
    for (int i = 0; i < n; i++) {
      int cp = switch (r.nextInt(4)) {
        case 0 -> 0x20 + r.nextInt(0x5f);
        case 1 -> r.nextInt(0x800);
        case 2 -> 0xe000 + r.nextInt(0x2000);
        default -> 0x10000 + r.nextInt(0xfffff);
      };
      b.appendCodePoint(cp);
    }
    return b.toString();
  }

  private static CborSimple randomSimple(Random r) {
    int v = r.nextInt(2) == 0 ? 20 + r.nextInt(4) : (r.nextInt(2) == 0 ? r.nextInt(20) : 32 + r.nextInt(224));
    return new CborSimple(v);
  }

  private static double randomDouble(Random r) {
    return switch (r.nextInt(8)) {
      case 0 -> Double.NaN;
      case 1 -> r.nextBoolean() ? Double.POSITIVE_INFINITY : Double.NEGATIVE_INFINITY;
      case 2 -> r.nextBoolean() ? 0.0 : -0.0;
      case 3 -> Float.float16ToFloat((short) r.nextInt(0x10000));
      case 4 -> Float.intBitsToFloat(r.nextInt());
      default -> Double.longBitsToDouble(r.nextLong());
    };
  }
}
