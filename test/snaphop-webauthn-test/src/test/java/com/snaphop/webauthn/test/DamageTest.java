package com.snaphop.webauthn.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.snaphop.webauthn.WebauthnAssertion;
import com.snaphop.webauthn.WebauthnException;
import com.snaphop.webauthn.WebauthnRegistration;
import com.snaphop.webauthn.test.Oracles.Verdicts;
import com.snaphop.webauthn.test.TestAuthenticator.Assertion;
import com.snaphop.webauthn.test.TestAuthenticator.Kind;
import com.snaphop.webauthn.test.TestAuthenticator.Registration;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/// Real ceremonies with random damage: a bit flipped, a byte changed, cut
/// short, a byte added or taken out, in any part. This library must refuse
/// with a [WebauthnException] and nothing else, and must never accept what
/// either oracle refuses. How often the three disagree is printed;
/// `-Ddamage.show=true` shows each disagreement.
///
/// `-Ddamage.iterations=N` sets how many of each (300 by default).
class DamageTest {

  static final int ITERATIONS = Integer.getInteger("damage.iterations", 300);
  static final byte[] USER = "user-1".getBytes(StandardCharsets.UTF_8);
  static final Kind[] KINDS = {Kind.ES256, Kind.ED25519, Kind.RS256};

  @Test
  void registrations() {
    Random random = new Random(11);
    Map<String, Integer> tally = new TreeMap<>();
    for (int i = 0; i < ITERATIONS; i++) {
      Registration r = new Registration(KINDS[i % KINDS.length], random);
      WebauthnRegistration whole = r.build();
      byte[] clientData = whole.clientDataJson();
      byte[] attestationObject = whole.attestationObject();
      if (random.nextInt(3) == 0) {
        clientData = damage(random, clientData);
      } else {
        attestationObject = damage(random, attestationObject);
      }
      byte[] c = clientData;
      byte[] o = attestationObject;
      ours(() -> Oracles.OURS.register(WebauthnRegistration.of(c, o), r.challenge, USER), c, o);
      Verdicts v = Oracles.register(c, o, r.challenge, USER, r.credentialId);
      assertEquals(false, v.oursLooser(), () -> "Accepted by us and refused by an oracle: " + HexFormat.of().formatHex(o) + "\n  " + v.summary());
      tally.merge(pattern(v), 1, Integer::sum);
      if (Boolean.getBoolean("damage.show") && !v.agree()) {
        System.out.println(pattern(v) + " " + v.summary());
      }
    }
    System.out.println("Damaged registrations (ours, webauthn4j, Yubico): " + tally);
  }

  @Test
  void signIns() {
    Random random = new Random(12);
    Map<String, Integer> tally = new TreeMap<>();
    for (int i = 0; i < ITERATIONS; i++) {
      Registration r = new Registration(KINDS[i % KINDS.length], random);
      Oracles.Stored stored = OracleTest.store(r);
      Assertion a = new Assertion(r, random);
      int part = random.nextInt(4);
      switch (part) {
        case 0 -> a.afterSigning = b -> damage(random, b);
        case 1 -> a.clientDataAfterSigning = b -> damage(random, b);
        case 2 -> a.signatureChange = b -> damage(random, b);
        default -> a.authenticatorDataChange = b -> damage(random, b);
      }
      WebauthnAssertion response = a.build();
      ours(() -> Oracles.OURS.signIn(response, a.challenge, stored.ours()), response.authenticatorData(), response.signature());
      Verdicts v = Oracles.signIn(stored, response, a.challenge);
      assertEquals(false, v.oursLooser(), () -> "Accepted by us and refused by an oracle: " + v.summary());
      tally.merge(pattern(v), 1, Integer::sum);
    }
    System.out.println("Damaged sign-ins (ours, webauthn4j, Yubico): " + tally);
  }

  /// Our verdict must be an answer or a WebauthnException, never another exception.
  static void ours(Oracles.Ceremony c, byte[] a, byte[] b) {
    try {
      c.run();
    } catch (WebauthnException e) {
      // refused, as it may be
    } catch (Exception | Error e) {
      throw new AssertionError("Not a WebauthnException for " + HexFormat.of().formatHex(a) + " / " + HexFormat.of().formatHex(b), e);
    }
  }

  static String pattern(Verdicts v) {
    return (v.ours().accepted() ? "A" : "R") + (v.webauthn4j().accepted() ? "A" : "R") + (v.yubico().accepted() ? "A" : "R");
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
