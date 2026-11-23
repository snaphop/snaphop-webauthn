package com.snaphop.cbor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;
import org.junit.jupiter.api.Test;

/// Random values, written every legal way, read back as the same value;
/// and those encodings damaged at random, which must be read or refused
/// with a [CborParseException] and nothing else (no index errors, no
/// running out of memory or stack).
///
/// `-Dfuzz.iterations=N` sets how many values (2000 by default).
class FuzzTest {

  static final int ITERATIONS = Integer.getInteger("fuzz.iterations", 2000);
  static final CborReader READER = CborReader.builder().build();
  static final CborReader CANONICAL = CborReader.builder().mode(CborReader.Mode.CANONICAL).build();

  @Test
  void roundTrip() {
    Random random = new Random(8949);
    for (int i = 0; i < ITERATIONS; i++) {
      CborValue value = Encoder.randomValue(random, 4);
      byte[] canonical = Encoder.canonical(value);
      assertEquals(value, READER.read(canonical), () -> HexFormat.of().formatHex(canonical));
      assertEquals(value, CANONICAL.read(canonical), () -> HexFormat.of().formatHex(canonical));
      Encoder any = Encoder.any(random);
      byte[] bytes = any.encode(value);
      String hex = HexFormat.of().formatHex(bytes);
      assertEquals(value, READER.read(bytes), hex);
      assertEquals(bytes.length, READER.readPrefix(bytes, 0).end(), hex);
      if (any.wroteNonCanonical) {
        assertThrows(CborParseException.class, () -> CANONICAL.read(bytes), hex);
      } else {
        assertEquals(value, CANONICAL.read(bytes), hex);
      }
    }
  }

  @Test
  void damaged() {
    Random random = new Random(7049);
    int refused = 0;
    for (int i = 0; i < ITERATIONS * 5; i++) {
      byte[] bytes = Encoder.any(random).encode(Encoder.randomValue(random, 4));
      byte[] damaged = damage(random, bytes);
      for (CborReader reader : new CborReader[] {READER, CANONICAL}) {
        try {
          CborValue value = reader.read(damaged);
          // What is read must be what a clean encoding of it reads as.
          assertEquals(value, READER.read(Encoder.canonical(value)));
        } catch (CborParseException e) {
          refused++;
          if (e.offset() < 0 || e.offset() > damaged.length) {
            fail("Offset " + e.offset() + " outside " + damaged.length + " bytes: " + HexFormat.of().formatHex(damaged));
          }
        } catch (RuntimeException | StackOverflowError | OutOfMemoryError e) {
          throw new AssertionError("Not a CborParseException for " + HexFormat.of().formatHex(damaged), e);
        }
      }
    }
    // Most damage is refused; if not, the damage isn't damaging.
    assertEquals(true, refused > ITERATIONS * 5, "refused " + refused);
  }

  @Test
  void randomBytes() {
    Random random = new Random(42);
    for (int i = 0; i < ITERATIONS * 10; i++) {
      byte[] bytes = new byte[random.nextInt(40)];
      random.nextBytes(bytes);
      try {
        READER.read(bytes);
      } catch (CborParseException e) {
        // fine
      } catch (RuntimeException | StackOverflowError e) {
        throw new AssertionError("Not a CborParseException for " + HexFormat.of().formatHex(bytes), e);
      }
    }
  }

  static byte[] damage(Random random, byte[] bytes) {
    if (bytes.length == 0) {
      return new byte[] {(byte) random.nextInt(256)};
    }
    byte[] out = bytes.clone();
    switch (random.nextInt(6)) {
      case 0 -> out[random.nextInt(out.length)] ^= (byte) (1 << random.nextInt(8));
      case 1 -> out[random.nextInt(out.length)] = (byte) random.nextInt(256);
      case 2 -> out = Arrays.copyOf(out, random.nextInt(out.length));
      case 3 -> {
        int at = random.nextInt(out.length + 1);
        byte[] longer = new byte[out.length + 1];
        System.arraycopy(out, 0, longer, 0, at);
        longer[at] = (byte) random.nextInt(256);
        System.arraycopy(out, at, longer, at + 1, out.length - at);
        out = longer;
      }
      case 4 -> {
        int at = random.nextInt(out.length);
        byte[] shorter = new byte[out.length - 1];
        System.arraycopy(out, 0, shorter, 0, at);
        System.arraycopy(out, at + 1, shorter, at, out.length - at - 1);
        out = shorter;
      }
      default -> out[random.nextInt(out.length)] = (byte) new int[] {0xff, 0x1f, 0x5f, 0x9f, 0xbf, 0xf8, 0x1b, 0x5b}[random.nextInt(8)];
    }
    return out;
  }
}
