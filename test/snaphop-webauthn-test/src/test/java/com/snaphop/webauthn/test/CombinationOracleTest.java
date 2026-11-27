package com.snaphop.webauthn.test;

import static com.snaphop.webauthn.test.TestAuthenticator.BE;
import static com.snaphop.webauthn.test.TestAuthenticator.BS;
import static com.snaphop.webauthn.test.TestAuthenticator.ED;
import static com.snaphop.webauthn.test.TestAuthenticator.UP;
import static com.snaphop.webauthn.test.TestAuthenticator.UV;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.snaphop.webauthn.test.Oracles.Verdicts;
import com.snaphop.webauthn.test.TestAuthenticator.Assertion;
import com.snaphop.webauthn.test.TestAuthenticator.ClientDataJson;
import com.snaphop.webauthn.test.TestAuthenticator.Kind;
import com.snaphop.webauthn.test.TestAuthenticator.Registration;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/// Registrations and sign-ins with several things changed at once, checked
/// by this library and both oracles (set up as [Oracles] says). What this
/// library accepts, both must accept; and where an oracle accepts what this
/// library refuses, the ceremony must have a change that [OracleTest]
/// already explains for that oracle.
///
/// `-Dcombinations.iterations=N` sets how many of each (500 by default);
/// `-Dcombinations.show=true` prints each disagreement.
class CombinationOracleTest {

  static final int ITERATIONS = Integer.getInteger("combinations.iterations", 500);
  static final byte[] USER = "user-1".getBytes(StandardCharsets.UTF_8);
  static final Kind[] KINDS = {Kind.ES256, Kind.ES384, Kind.ED25519, Kind.RS256};

  @Test
  void registrations() {
    Random random = new Random(21);
    Map<String, Integer> tally = new TreeMap<>();
    for (int i = 0; i < ITERATIONS; i++) {
      Registration r = new Registration(KINDS[random.nextInt(KINDS.length)], random);
      List<String> changes = new ArrayList<>();
      clientData(random, r.clientData, changes);
      r.flags = TestAuthenticator.AT | flags(random, changes);
      r.signCount = random.nextInt(3) == 0 ? 0 : random.nextInt(1000);
      if (random.nextInt(8) == 0) {
        r.flags |= ED;
        r.extensions = TestCbor.encode(Map.of("credProtect", 2));
        changes.add("extensions");
      }
      if (random.nextInt(10) == 0) {
        r.attStmt.put("sig", new byte[] {1});
        changes.add("none with a statement");
      }
      if (random.nextInt(10) == 0) {
        r.credentialId = new byte[1024];
        changes.add("credential ID 1024");
      }
      Verdicts v = OracleTest.registerAll(r);
      record(v, changes, tally, "registration");
    }
    tally.forEach((k, n) -> System.out.println("Registration combinations, " + k + ": " + n));
  }

  @Test
  void signIns() {
    Random random = new Random(22);
    Map<String, Integer> tally = new TreeMap<>();
    for (int i = 0; i < ITERATIONS; i++) {
      Registration r = new Registration(KINDS[random.nextInt(KINDS.length)], random);
      r.flags |= random.nextBoolean() ? BE | (random.nextBoolean() ? BS : 0) : 0;
      r.signCount = random.nextInt(3) == 0 ? 0 : random.nextInt(1000);
      Oracles.Stored stored = OracleTest.store(r);
      Assertion a = new Assertion(r, random);
      List<String> changes = new ArrayList<>();
      clientData(random, a.clientData, changes);
      a.flags = flags(random, changes);
      if (random.nextInt(5) != 0) {
        a.flags = (a.flags & ~(BE | BS)) | (r.flags & BE) | ((r.flags & BE) != 0 ? a.flags & BS : 0);
      } else if (((a.flags ^ r.flags) & BE) != 0) {
        changes.add((a.flags & BE) != 0 ? "became backup eligible" : "lost backup eligibility");
      }
      long s = r.signCount;
      a.signCount = switch (random.nextInt(5)) {
        case 0 -> 0;
        case 1 -> s;
        case 2 -> Math.max(0, s - 1);
        default -> s == 0 ? 0 : s + 1 + random.nextInt(10);
      };
      if (a.signCount <= s && !(a.signCount == 0 && s == 0)) {
        changes.add("counter not increased");
      }
      if (random.nextInt(8) == 0) {
        a.flags |= ED;
        a.extensions = TestCbor.encode(Map.of("devicePubKey", new byte[] {1}));
        changes.add("extensions");
      }
      switch (random.nextInt(4)) {
        case 0 -> a.userHandle = USER;
        case 1 -> {
          if (random.nextInt(4) == 0) {
            a.userHandle = "user-2".getBytes(StandardCharsets.UTF_8);
            changes.add("other user handle");
          }
        }
        default -> { }
      }
      if (random.nextInt(12) == 0) {
        a.signatureChange = sig -> {
          byte[] t = sig.clone();
          t[t.length / 2] ^= 4;
          return t;
        };
        changes.add("signature changed");
      }
      Verdicts v = Oracles.signIn(stored, a.build(), a.challenge);
      record(v, changes, tally, "sign-in");
    }
    tally.forEach((k, n) -> System.out.println("Sign-in combinations, " + k + ": " + n));
  }

  /// Client data with origins, crossOrigin and topOrigin changed at random.
  static void clientData(Random random, ClientDataJson cd, List<String> changes) {
    switch (random.nextInt(10)) {
      case 0 -> {
        cd.origin = "https://evil.example";
        changes.add("other origin");
      }
      case 1 -> {
        cd.origin = "https://example.org/";
        changes.add("origin with a slash");
      }
      default -> { }
    }
    switch (random.nextInt(8)) {
      case 0 -> {
        cd.crossOrigin = true;
        changes.add("crossOrigin true");
      }
      case 1 -> cd.crossOrigin = null;
      default -> { }
    }
    if (random.nextInt(8) == 0) {
      cd.topOrigin = "https://example.com";
      changes.add("topOrigin");
    }
    if (random.nextInt(5) == 0) {
      cd.extra = ",\"other_keys_can_be_added_here\":\"x\"";
    }
  }

  /// Random UP, UV, BE and BS flags and reserved bits, naming the changes.
  static int flags(Random random, List<String> changes) {
    int flags = UP | UV;
    if (random.nextInt(10) == 0) {
      flags &= ~UP;
      changes.add("no UP");
    }
    if (random.nextInt(10) == 0) {
      flags &= ~UV;
      changes.add("no UV");
    }
    if (random.nextBoolean()) {
      flags |= BE | (random.nextBoolean() ? BS : 0);
    } else if (random.nextInt(10) == 0) {
      flags |= BS;
      changes.add("BS without BE");
    }
    if (random.nextInt(8) == 0) {
      flags |= random.nextBoolean() ? 0x02 : 0x20;
      changes.add("a reserved flag");
    }
    return flags;
  }

  /// The changes each oracle is known to accept where this library refuses,
  /// as [OracleTest] explains case by case.
  static final List<String> WEBAUTHN4J_ACCEPTS = List.of("origin with a slash", "other user handle");
  static final List<String> YUBICO_ACCEPTS = List.of("crossOrigin true", "topOrigin", "none with a statement", "credential ID 1024");

  /// Checks the verdicts: what this library accepts, both oracles accept;
  /// and where an oracle accepts what it refuses, one of the changes is one
  /// that oracle is known to accept.
  static void record(Verdicts v, List<String> changes, Map<String, Integer> tally, String what) {
    String pattern = (v.ours().accepted() ? "A" : "R") + (v.webauthn4j().accepted() ? "A" : "R") + (v.yubico().accepted() ? "A" : "R");
    if (Boolean.getBoolean("combinations.show") && !v.agree()) {
      System.out.println(what + " " + pattern + " " + changes + "\n  " + v.summary());
    }
    assertEquals(false, v.oursLooser(), () -> "Accepted by us and refused by an oracle, " + what + " with " + changes + ":\n  " + v.summary());
    if (!v.ours().accepted()) {
      if (v.webauthn4j().accepted()) {
        tally.merge("webauthn4j accepts " + explained(changes, WEBAUTHN4J_ACCEPTS, "webauthn4j", v), 1, Integer::sum);
      }
      if (v.yubico().accepted()) {
        tally.merge("Yubico accepts " + explained(changes, YUBICO_ACCEPTS, "Yubico", v), 1, Integer::sum);
      }
    }
    tally.merge(pattern, 1, Integer::sum);
  }

  /// The known leniencies among the changes; there must be one.
  static String explained(List<String> changes, List<String> known, String oracle, Verdicts v) {
    List<String> why = changes.stream().filter(known::contains).toList();
    assertEquals(false, why.isEmpty(), () -> oracle + " accepts what we refuse, and none of " + changes + " explains it:\n  " + v.summary());
    return String.join(" or ", why);
  }
}
