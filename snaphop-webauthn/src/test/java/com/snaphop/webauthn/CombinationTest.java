package com.snaphop.webauthn;

import static com.snaphop.webauthn.TestAuthenticator.AT;
import static com.snaphop.webauthn.TestAuthenticator.BE;
import static com.snaphop.webauthn.TestAuthenticator.BS;
import static com.snaphop.webauthn.TestAuthenticator.ED;
import static com.snaphop.webauthn.TestAuthenticator.UP;
import static com.snaphop.webauthn.TestAuthenticator.UV;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.snaphop.webauthn.TestAuthenticator.Assertion;
import com.snaphop.webauthn.TestAuthenticator.ClientDataJson;
import com.snaphop.webauthn.TestAuthenticator.Kind;
import com.snaphop.webauthn.TestAuthenticator.Registration;
import com.snaphop.webauthn.WebauthnException.Reason;
import com.snaphop.webauthn.WebauthnRelyingParty.Attestation;
import com.snaphop.webauthn.WebauthnRelyingParty.CrossOrigin;
import com.snaphop.webauthn.WebauthnRelyingParty.RegistrationMediation;
import com.snaphop.webauthn.WebauthnRelyingParty.SignCountCheck;
import com.snaphop.webauthn.WebauthnRelyingParty.UserVerification;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

/// Random relying parties, and random registrations and sign-ins with many
/// things changed at once, where [CeremonyTest] changes one at a time. A
/// small model of WebAuthn's rules says which reasons apply: none, and the
/// ceremony must be accepted with what the model expects; some, and it must
/// be refused for one of them. Each credential registered then signs in
/// several times, each sign-in starting from what the last one returned.
///
/// `-Dcombinations.iterations=N` sets how many relying parties (3000 by
/// default) and `-Dcombinations.seed=S` the first seed; a failure names the
/// seed that reproduces it.
class CombinationTest {

  static final int ITERATIONS = Integer.getInteger("combinations.iterations", 3000);
  static final long SEED = Long.getLong("combinations.seed", 1);

  static final String LOGIN = "https://login.example.org";
  static final List<String> ORIGINS = List.of(TestAuthenticator.ORIGIN, LOGIN, "https://evil.example");
  static final List<String> TOP_ORIGINS = List.of("https://example.com", "https://partner.example", "https://evil.example");
  static final List<String> FORMATS = List.of("none", "none", "none", "packed", "apple", "nne");
  static final byte[] USER = CeremonyTest.USER;

  /// A relying party's settings, kept to model what it accepts.
  record Party(WebauthnRelyingParty rp, Set<String> origins, Set<String> topOrigins, CrossOrigin crossOrigin,
      UserVerification userVerification, Set<WebauthnAlgorithm> algorithms, Attestation attestation, SignCountCheck signCountCheck) {

    static Party random(Random r) {
      Set<String> origins = new LinkedHashSet<>();
      while (origins.isEmpty()) {
        for (String o : ORIGINS.subList(0, 2)) {
          if (r.nextInt(3) != 0) {
            origins.add(o);
          }
        }
      }
      Set<String> topOrigins = new LinkedHashSet<>();
      for (String o : TOP_ORIGINS.subList(0, 2)) {
        if (r.nextInt(3) == 0) {
          topOrigins.add(o);
        }
      }
      Set<WebauthnAlgorithm> algorithms = EnumSet.noneOf(WebauthnAlgorithm.class);
      while (algorithms.isEmpty()) {
        for (WebauthnAlgorithm a : WebauthnAlgorithm.values()) {
          if (r.nextInt(4) != 0) {
            algorithms.add(a);
          }
        }
      }
      CrossOrigin crossOrigin = pick(r, CrossOrigin.values());
      UserVerification uv = pick(r, UserVerification.values());
      Attestation attestation = pick(r, Attestation.values());
      SignCountCheck signCount = pick(r, SignCountCheck.values());
      WebauthnRelyingParty.Builder b = WebauthnRelyingParty.builder().id(TestAuthenticator.RP_ID)
          .crossOrigin(crossOrigin).userVerification(uv).algorithms(algorithms.toArray(WebauthnAlgorithm[]::new))
          .attestation(attestation).signCountCheck(signCount);
      origins.forEach(b::origin);
      topOrigins.forEach(b::topOrigin);
      return new Party(b.build(), origins, topOrigins, crossOrigin, uv, algorithms, attestation, signCount);
    }
  }

  @Test
  void ceremonies() {
    Map<String, Integer> tally = new TreeMap<>();
    for (int i = 0; i < ITERATIONS; i++) {
      long seed = SEED + i;
      Random r = new Random(seed);
      Party party = Party.random(r);
      List<String> steps = new ArrayList<>();
      try {
        WebauthnCredential credential = register(r, party, steps, tally);
        if (credential == null) {
          continue;
        }
        Registration registration = registrations.get(registrations.size() - 1);
        for (int n = r.nextInt(5); n > 0; n--) {
          credential = signIn(r, party, registration, credential, steps, tally);
          if (r.nextInt(4) == 0) {
            credential = stored(credential);
          }
        }
      } catch (AssertionError e) {
        throw new AssertionError("seed " + seed + ": " + e.getMessage() + "\n  " + party + "\n  " + String.join("\n  ", steps), e);
      }
    }
    tally.forEach((k, v) -> System.out.println("Ceremony combinations, " + k + ": " + v));
  }

  private final List<Registration> registrations = new ArrayList<>();

  /// Whether this ceremony is free of faults: a third are, so that the
  /// accepting paths are well covered.
  private boolean clean;

  /// A fault, one time in `oneIn`, never in a clean ceremony.
  boolean fault(Random r, int oneIn) {
    return r.nextInt(oneIn) == 0 && !clean;
  }

  /// A random registration, checked against the model; the credential when
  /// it is accepted.
  @Nullable WebauthnCredential register(Random r, Party p, List<String> steps, Map<String, Integer> tally) {
    clean = r.nextInt(3) == 0;
    Kind kind = pick(r, Kind.values());
    while (clean && !p.algorithms().contains(kind.algorithm)) {
      kind = pick(r, Kind.values());
    }
    Registration reg = new Registration(kind, r);
    registrations.add(reg);
    Set<Reason> reasons = EnumSet.noneOf(Reason.class);
    clientData(r, p, reg.clientData, "webauthn.create", reasons);
    if (fault(r, 10)) {
      reg.rpIdHash = TestAuthenticator.sha256("evil.example".getBytes(StandardCharsets.UTF_8));
      reasons.add(Reason.RP_ID);
    }
    reg.flags = AT | randomFlags(r);
    RegistrationMediation mediation = r.nextInt(4) == 0 ? RegistrationMediation.CONDITIONAL : RegistrationMediation.STANDARD;
    flags(p, reg.flags, mediation == RegistrationMediation.STANDARD, reasons);
    reg.signCount = r.nextInt(3) == 0 ? 0 : r.nextInt(3) == 0 ? 0xffff_ffffL : r.nextInt(1000);
    int idLength = switch (r.nextInt(12)) {
      case 0 -> 1;
      case 1 -> 1023;
      case 2 -> 1024;
      case 3 -> 0;
      default -> 16 + r.nextInt(48);
    };
    if (clean && (idLength == 0 || idLength > 1023)) {
      idLength = 32;
    }
    reg.credentialId = new byte[idLength];
    r.nextBytes(reg.credentialId);
    if (idLength == 0 || idLength > 1023) {
      reasons.add(Reason.CREDENTIAL_ID);
    }
    if (!p.algorithms().contains(kind.algorithm)) {
      reasons.add(Reason.PUBLIC_KEY);
    }
    extensions(r, reg.flags, b -> reg.flags = b, e -> reg.extensions = e);
    reg.fmt = clean && p.attestation() == Attestation.NONE ? "none" : pick(r, FORMATS.subList(0, clean ? 5 : 6).toArray(String[]::new));
    if (fault(r, 4)) {
      reg.attStmt.put("sig", new byte[] {1});
    }
    if (reg.fmt.equals("none") ? !reg.attStmt.isEmpty()
        : p.attestation() == Attestation.NONE || reg.fmt.equals("nne")) {
      reasons.add(Reason.ATTESTATION);
    }
    String step = "register " + kind + " " + mediation + " flags " + Integer.toHexString(reg.flags) + " count " + reg.signCount
        + " id " + idLength + " fmt " + reg.fmt + " " + reg.attStmt.keySet() + " " + new String(reg.clientData.bytes(), StandardCharsets.UTF_8)
        + (reasons.contains(Reason.RP_ID) ? " other RP ID" : "") + ", expecting " + reasons;
    steps.add(step);
    WebauthnCredential c = outcome(reasons, () -> p.rp().register(reg.build(), reg.challenge, USER, mediation), tally, "registration");
    if (c != null) {
      assertEquals(kind.algorithm, c.algorithm());
      assertArrayEquals(reg.credentialId, c.credentialId());
      assertArrayEquals(reg.publicKeyCose(), c.publicKeyCose());
      assertArrayEquals(USER, c.userHandle());
      assertEquals(reg.signCount, c.signCount());
      assertEquals((reg.flags & BE) != 0, c.backupEligible());
      assertEquals((reg.flags & BS) != 0, c.backedUp());
      assertEquals(reg.fmt, c.attestationFormat());
    }
    return c;
  }

  /// A random sign-in with a registered credential, checked against the
  /// model; the credential to store next.
  WebauthnCredential signIn(Random r, Party p, Registration reg, WebauthnCredential c, List<String> steps, Map<String, Integer> tally) {
    Assertion a = new Assertion(reg, r);
    clean = r.nextInt(3) == 0;
    Set<Reason> reasons = EnumSet.noneOf(Reason.class);
    if (fault(r, 12)) {
      a.credentialId[r.nextInt(a.credentialId.length)] ^= 1;
      reasons.add(Reason.CREDENTIAL_ID);
    }
    boolean discoverable = r.nextBoolean();
    a.userHandle = switch (r.nextInt(8)) {
      case 0 -> "user-2".getBytes(StandardCharsets.UTF_8);
      case 1, 2, 3 -> null;
      default -> USER.clone();
    };
    if (clean) {
      a.userHandle = discoverable || a.userHandle != null ? USER.clone() : null;
    }
    if (a.userHandle == null ? discoverable : !java.util.Arrays.equals(a.userHandle, USER)) {
      reasons.add(Reason.USER_HANDLE);
    }
    clientData(r, p, a.clientData, "webauthn.get", reasons);
    if (fault(r, 10)) {
      a.rpIdHash = TestAuthenticator.sha256("evil.example".getBytes(StandardCharsets.UTF_8));
      reasons.add(Reason.RP_ID);
    }
    // Mostly what the credential was registered with.
    a.flags = randomFlags(r);
    if (!fault(r, 6)) {
      a.flags = (a.flags & ~BE) | (c.backupEligible() ? BE : 0);
      if (!c.backupEligible()) {
        a.flags &= ~BS;
      }
    }
    flags(p, a.flags, true, reasons);
    if (((a.flags & BE) != 0) != c.backupEligible()) {
      reasons.add(Reason.BACKUP);
    }
    if (fault(r, 15)) {
      a.flags |= AT;
      byte[] header = new byte[18];
      header[17] = 1;
      a.attested = CeremonyTest.concat(CeremonyTest.concat(header, new byte[] {7}), TestCbor.encode(TestAuthenticator.coseKey(a.kind, a.keys)));
      reasons.add(Reason.AUTHENTICATOR_DATA);
    }
    extensions(r, a.flags, b -> a.flags = b, e -> a.extensions = e);
    long stored = c.signCount();
    a.signCount = switch (r.nextInt(6)) {
      case 0 -> 0;
      case 1 -> stored;
      case 2 -> Math.max(0, stored - 1 - r.nextInt(3));
      case 3 -> Math.min(0xffff_ffffL, stored + 1 + r.nextInt(1000));
      default -> stored == 0 ? 0 : Math.min(0xffff_ffffL, stored + 1);
    };
    WebauthnSignIn.SignCount expectedCount = stored == 0 && a.signCount == 0 ? WebauthnSignIn.SignCount.ZERO
        : a.signCount > stored ? WebauthnSignIn.SignCount.INCREASED : WebauthnSignIn.SignCount.NOT_INCREASED;
    if (expectedCount == WebauthnSignIn.SignCount.NOT_INCREASED && p.signCountCheck() == SignCountCheck.REFUSE) {
      reasons.add(Reason.SIGN_COUNT);
    }
    switch (fault(r, 7) ? r.nextInt(3) : 3) {
      case 0 -> {
        a.signatureChange = s -> {
          byte[] t = s.clone();
          t[t.length / 2] ^= 4;
          return t;
        };
        reasons.add(Reason.SIGNATURE);
      }
      case 1 -> {
        a.afterSigning = b -> {
          byte[] t = b.clone();
          t[32] ^= 0x20;
          return t;
        };
        reasons.add(Reason.SIGNATURE);
      }
      case 2 -> {
        a.clientDataAfterSigning = b -> new String(b, StandardCharsets.UTF_8).replace("}", ",\"x\":1}").getBytes(StandardCharsets.UTF_8);
        reasons.add(Reason.SIGNATURE);
      }
      default -> { }
    }
    steps.add("sign in" + (discoverable ? " discoverable" : "") + " flags " + Integer.toHexString(a.flags) + " count " + a.signCount
        + " stored " + stored + " handle " + (a.userHandle == null ? "none" : new String(a.userHandle, StandardCharsets.UTF_8))
        + " " + new String(a.clientData.bytes(), StandardCharsets.UTF_8) + ", expecting " + reasons);
    WebauthnAssertion response = a.build();
    WebauthnSignIn signIn = outcome(reasons,
        () -> discoverable ? p.rp().signInDiscoverable(response, a.challenge, c) : p.rp().signIn(response, a.challenge, c), tally, "sign-in");
    if (signIn == null) {
      return c;
    }
    assertEquals(expectedCount, signIn.signCount());
    assertEquals((a.flags & UV) != 0, signIn.userVerified());
    WebauthnCredential next = signIn.credential();
    assertEquals(Math.max(stored, a.signCount), next.signCount());
    assertEquals((a.flags & BS) != 0, next.backedUp());
    assertEquals(c.backupEligible(), next.backupEligible());
    assertArrayEquals(c.credentialId(), next.credentialId());
    assertArrayEquals(c.publicKeyCose(), next.publicKeyCose());
    assertArrayEquals(c.userHandle(), next.userHandle());
    return next;
  }

  /// The credential as stored and read back.
  static WebauthnCredential stored(WebauthnCredential c) {
    WebauthnCredential back = WebauthnCredential.builder(c.credentialId(), c.publicKeyCose(), c.userHandle())
        .signCount(c.signCount()).backupEligible(c.backupEligible()).backedUp(c.backedUp())
        .aaguid(c.aaguid()).attestationFormat(c.attestationFormat()).build();
    assertEquals(c, back);
    return back;
  }

  /// Random client data, and the reasons it is refused for.
  void clientData(Random r, Party p, ClientDataJson cd, String type, Set<Reason> reasons) {
    if (fault(r, 15)) {
      cd.type = type.equals("webauthn.get") ? "webauthn.create" : "webauthn.get";
      reasons.add(Reason.TYPE);
    }
    if (fault(r, 15)) {
      cd.challenge = TestAuthenticator.b64(new byte[32]);
      reasons.add(Reason.CHALLENGE);
    }
    cd.origin = pick(r, ORIGINS.toArray(String[]::new));
    if (!fault(r, 3)) {
      cd.origin = pick(r, p.origins().toArray(String[]::new));
    }
    if (!p.origins().contains(cd.origin)) {
      reasons.add(Reason.ORIGIN);
    }
    int cross = r.nextInt(5);
    cd.crossOrigin = cross == 0 ? null : cross == 1 && (!clean || p.crossOrigin() == CrossOrigin.ALLOW);
    cd.topOrigin = fault(r, 4) ? pick(r, TOP_ORIGINS.toArray(String[]::new)) : null;
    if (clean && Boolean.TRUE.equals(cd.crossOrigin) && !p.topOrigins().isEmpty()) {
      cd.topOrigin = pick(r, p.topOrigins().toArray(String[]::new));
    }
    boolean crossOrigin = Boolean.TRUE.equals(cd.crossOrigin);
    String top = cd.topOrigin;
    if ((crossOrigin && p.crossOrigin() == CrossOrigin.REFUSE)
        || (crossOrigin && top == null && !p.topOrigins().isEmpty())
        || (top != null && (!crossOrigin || !p.topOrigins().contains(top)))) {
      reasons.add(Reason.CROSS_ORIGIN);
    }
    if (r.nextInt(5) == 0) {
      cd.extra = ",\"other_keys_can_be_added_here\":\"x\",\"n\":[1,{\"a\":null}]";
    }
  }

  /// Random flags among UP, UV, BE, BS and the two reserved ones, which
  /// must be ignored.
  int randomFlags(Random r) {
    int flags = 0;
    if (!fault(r, 8)) {
      flags |= UP;
    }
    if (!fault(r, 5)) {
      flags |= UV;
    }
    if (r.nextBoolean()) {
      flags |= BE;
      if (r.nextBoolean()) {
        flags |= BS;
      }
    } else if (fault(r, 10)) {
      flags |= BS;
    }
    if (r.nextInt(10) == 0) {
      flags |= 0x02;
    }
    if (r.nextInt(10) == 0) {
      flags |= 0x20;
    }
    return flags;
  }

  /// The reasons flags are refused for, in a registration or sign-in.
  static void flags(Party p, int flags, boolean userPresenceRequired, Set<Reason> reasons) {
    if (userPresenceRequired && (flags & UP) == 0) {
      reasons.add(Reason.USER_PRESENCE);
    }
    if (p.userVerification() == UserVerification.REQUIRED && (flags & UV) == 0) {
      reasons.add(Reason.USER_VERIFICATION);
    }
    if ((flags & BS) != 0 && (flags & BE) == 0) {
      reasons.add(Reason.BACKUP);
    }
  }

  /// Extensions, with the ED flag, now and then.
  static void extensions(Random r, int flags, java.util.function.IntConsumer setFlags, java.util.function.Consumer<byte[]> set) {
    if (r.nextInt(6) == 0) {
      setFlags.accept(flags | ED);
      set.accept(TestCbor.encode(Map.of("credProtect", 1 + r.nextInt(3))));
    }
  }

  /// The ceremony's result if the model expects none of `reasons`, after
  /// checking it is accepted; otherwise null, after checking it is refused
  /// for one of them.
  static <T> @Nullable T outcome(Set<Reason> reasons, Supplier<T> ceremony, Map<String, Integer> tally, String what) {
    T result;
    try {
      result = ceremony.get();
    } catch (WebauthnException e) {
      assertTrue(reasons.contains(e.reason()), () -> "Refused for " + e.reason() + " (" + e.getMessage() + "), expecting " + (reasons.isEmpty() ? "it accepted" : reasons));
      tally.merge(what + (reasons.size() == 1 ? " refused for " + e.reason() : " refused for one of several reasons"), 1, Integer::sum);
      return null;
    }
    assertTrue(reasons.isEmpty(), () -> "Accepted, expecting a refusal for " + reasons);
    tally.merge(what + " accepted", 1, Integer::sum);
    return result;
  }

  static <T> T pick(Random r, T[] values) {
    return values[r.nextInt(values.length)];
  }
}
