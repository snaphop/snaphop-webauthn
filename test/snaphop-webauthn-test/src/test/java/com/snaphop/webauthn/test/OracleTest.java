package com.snaphop.webauthn.test;

import static com.snaphop.webauthn.test.TestAuthenticator.AT;
import static com.snaphop.webauthn.test.TestAuthenticator.BE;
import static com.snaphop.webauthn.test.TestAuthenticator.BS;
import static com.snaphop.webauthn.test.TestAuthenticator.ED;
import static com.snaphop.webauthn.test.TestAuthenticator.UP;
import static com.snaphop.webauthn.test.TestAuthenticator.UV;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.snaphop.webauthn.test.Oracles.Verdicts;
import com.snaphop.webauthn.test.TestAuthenticator.Assertion;
import com.snaphop.webauthn.test.TestAuthenticator.Kind;
import com.snaphop.webauthn.test.TestAuthenticator.Registration;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/// Every ceremony is checked by this library and by both oracles, and their
/// verdicts compared. A case's `expected` is the three verdicts in order
/// (ours, webauthn4j, Yubico), `A` accepted and `R` refused; where they
/// differ, `why` says why, so a change on either side is noticed. What
/// this library accepts, both others must accept.
class OracleTest {

  static final byte[] USER = "user-1".getBytes(StandardCharsets.UTF_8);

  @ParameterizedTest
  @EnumSource(value = Kind.class, names = {"ES256", "ES384", "ED25519", "RS256"})
  void everyCommonKind(Kind kind) {
    Random random = new Random(kind.name().hashCode());
    for (int i = 0; i < 10; i++) {
      Registration r = new Registration(kind, random);
      r.flags |= random.nextBoolean() ? BE | (random.nextBoolean() ? BS : 0) : 0;
      r.signCount = random.nextInt(3) == 0 ? 0 : random.nextInt(1000);
      check("AAA", registerAll(r));
      Oracles.Stored stored = store(r);
      Assertion a = new Assertion(r, random);
      a.flags |= r.flags & BE;
      a.signCount = r.signCount == 0 ? 0 : r.signCount + 1 + random.nextInt(10);
      if (random.nextBoolean()) {
        a.userHandle = USER;
      }
      check("AAA", Oracles.signIn(stored, a.build(), a.challenge));
    }
  }

  enum RegistrationCase {
    WHOLE("AAA", ""),
    TYPE_GET("RRR", ""),
    CHALLENGE_OTHER("RRR", ""),
    CHALLENGE_PADDED("RAA",
        "Both oracles decode the challenge leniently, padding and all, and compare bytes; we compare the exact base64url text browsers write, which has no padding"),
    ORIGIN_OTHER("RRR", ""),
    ORIGIN_SLASH("RAR",
        "webauthn4j normalizes origins, so a slash at the end still matches"),
    CROSS_ORIGIN("RRA",
        "Yubico does not check crossOrigin"),
    CROSS_ORIGIN_ABSENT("AAA", ""),
    TOP_ORIGIN_WITHOUT_CROSS_ORIGIN("RRA",
        "Yubico does not read topOrigin"),
    ORIGIN_TWICE("RRR", ""),
    EXTRA_MEMBERS("AAA", ""),
    CLIENT_DATA_TRAILING("RRA",
        "Yubico reads the JSON object and ignores what follows it"),
    CLIENT_DATA_NOT_UTF8("RRA",
        "Yubico decodes bytes that are not UTF-8 as replacement characters"),
    RP_ID_OTHER("RRR", ""),
    NO_USER_PRESENCE("RRR", ""),
    NO_USER_VERIFICATION("RRR", ""),
    BACKED_UP_NOT_ELIGIBLE("RRR", ""),
    NO_ATTESTED_DATA("RRR", ""),
    TRAILING_BYTE("RRR", ""),
    EXTENSIONS("AAA", ""),
    EXTENSIONS_WITHOUT_FLAG("RRR", ""),
    FLAG_WITHOUT_EXTENSIONS("RAR",
        "webauthn4j reads an ED flag with nothing after it as no extensions"),
    NONE_WITH_STATEMENT("RRA",
        "Yubico does not require the \"none\" statement to be empty"),
    ATTESTATION_OBJECT_EXTRA_KEY("AAA", ""),
    ATTESTATION_OBJECT_DUPLICATE("RRR", ""),
    CREDENTIAL_ID_1023("AAA", ""),
    CREDENTIAL_ID_1024("RRA",
        "Yubico has no 1023-byte limit on credential IDs"),
    COSE_ALGORITHM_FOR_OTHER_CURVE("RAA",
        "Neither oracle checks that a key's alg goes with its crv"),
    COSE_POINT_NOT_ON_CURVE("RAA",
        "Neither oracle checks the point is on the curve when registering; such a key can never verify a signature"),
    COSE_COORDINATE_ABOVE_PRIME("RAA",
        "Neither oracle checks coordinates are below the prime when registering"),
    COSE_COORDINATE_SHORT("RAR",
        "webauthn4j accepts a coordinate shorter than the curve's size"),
    COSE_EXTRA_MEMBER("RAA", "Neither oracle requires public COSE keys to exclude optional parameters"),
    COSE_DUPLICATE_MEMBER("RAR",
        "webauthn4j's CBOR (Jackson) keeps the last of a key written twice"),
    COSE_KEY_NOT_CANONICAL("RAA", "Neither oracle requires the credential public key to use canonical CBOR");

    final String expected;
    final String why;

    RegistrationCase(String expected, String why) {
      this.expected = expected;
      this.why = why;
    }

    void change(Registration r) {
      switch (this) {
        case WHOLE -> { }
        case TYPE_GET -> r.clientData.type = "webauthn.get";
        case CHALLENGE_OTHER -> r.clientData.challenge = TestAuthenticator.b64(new byte[32]);
        case CHALLENGE_PADDED -> r.clientData.challenge += "=";
        case ORIGIN_OTHER -> r.clientData.origin = "https://evil.example";
        case ORIGIN_SLASH -> r.clientData.origin = "https://example.org/";
        case CROSS_ORIGIN -> r.clientData.crossOrigin = true;
        case CROSS_ORIGIN_ABSENT -> r.clientData.crossOrigin = null;
        case TOP_ORIGIN_WITHOUT_CROSS_ORIGIN -> r.clientData.topOrigin = "https://example.com";
        case ORIGIN_TWICE -> r.clientData.extra = ",\"origin\":\"https://evil.example\"";
        case EXTRA_MEMBERS -> r.clientData.extra = ",\"other_keys_can_be_added_here\":\"x\",\"tokenBinding\":{\"status\":\"supported\"}";
        case CLIENT_DATA_TRAILING -> r.clientDataChange = b -> Oracles.concat(b, "x".getBytes(StandardCharsets.UTF_8));
        case CLIENT_DATA_NOT_UTF8 -> r.clientDataChange = b -> Oracles.concat(b, new byte[] {(byte) 0xc3});
        case RP_ID_OTHER -> r.rpIdHash = TestAuthenticator.sha256("evil.example".getBytes(StandardCharsets.UTF_8));
        case NO_USER_PRESENCE -> r.flags &= ~UP;
        case NO_USER_VERIFICATION -> r.flags &= ~UV;
        case BACKED_UP_NOT_ELIGIBLE -> r.flags |= BS;
        case NO_ATTESTED_DATA -> r.flags &= ~AT;
        case TRAILING_BYTE -> r.trailing = new byte[] {0};
        case EXTENSIONS -> {
          r.flags |= ED;
          r.extensions = TestCbor.encode(Map.of("credProtect", 2));
        }
        case EXTENSIONS_WITHOUT_FLAG -> r.extensions = TestCbor.encode(Map.of("credProtect", 2));
        case FLAG_WITHOUT_EXTENSIONS -> r.flags |= ED;
        case NONE_WITH_STATEMENT -> r.attStmt.put("sig", new byte[] {0});
        case ATTESTATION_OBJECT_EXTRA_KEY -> r.attestationObjectChange = b -> {
          Map<Object, Object> o = new java.util.LinkedHashMap<>();
          o.put("fmt", "none");
          o.put("attStmt", Map.of());
          o.put("authData", r.authenticatorData());
          o.put("extra", 1);
          return TestCbor.encode(o);
        };
        case ATTESTATION_OBJECT_DUPLICATE -> r.attestationObjectChange = b -> {
          Map<Object, Object> o = new java.util.LinkedHashMap<>();
          o.put("fmt", "none");
          o.put("attStmt", Map.of());
          o.put("authData", r.authenticatorData());
          byte[] once = TestCbor.encode(o);
          // A fourth entry: "fmt" again.
          once[0] = (byte) 0xa4;
          return Oracles.concat(once, Oracles.concat(TestCbor.encode("fmt"), TestCbor.encode("packed")));
        };
        case CREDENTIAL_ID_1023 -> r.credentialId = new byte[1023];
        case CREDENTIAL_ID_1024 -> r.credentialId = new byte[1024];
        case COSE_ALGORITHM_FOR_OTHER_CURVE -> r.cose.put(3, -35);
        case COSE_POINT_NOT_ON_CURVE -> {
          byte[] y = ((byte[]) Objects.requireNonNull(r.cose.get(-3))).clone();
          y[31] ^= 1;
          r.cose.put(-3, y);
        }
        case COSE_COORDINATE_ABOVE_PRIME -> {
          BigInteger p = ((ECFieldFp) ((ECPublicKey) r.keys.getPublic()).getParams().getCurve().getField()).getP();
          r.cose.put(-2, TestAuthenticator.fixed(p, 32));
        }
        case COSE_COORDINATE_SHORT -> r.cose.put(-2, Arrays.copyOf((byte[]) Objects.requireNonNull(r.cose.get(-2)), 31));
        case COSE_EXTRA_MEMBER -> r.cose.put(2, new byte[] {1, 2, 3});
        case COSE_DUPLICATE_MEMBER -> {
          byte[] cose = TestCbor.encode(r.cose);
          cose[0] = (byte) 0xa6;
          r.coseBytes = Oracles.concat(cose, new byte[] {0x01, 0x02});
        }
        case COSE_KEY_NOT_CANONICAL -> {
          // The same key, its members in another order.
          Map<Object, Object> reordered = new java.util.LinkedHashMap<>();
          for (Object k : List.of(-3, -2, -1, 3, 1)) {
            reordered.put(k, r.cose.get(k));
          }
          r.cose = reordered;
        }
      }
    }
  }

  @ParameterizedTest
  @EnumSource
  void registration(RegistrationCase c) {
    Registration r = new Registration(Kind.ES256, new Random(c.name().hashCode()));
    c.change(r);
    assertEquals(c.expected.equals("AAA") || c.expected.equals("RRR"), c.why.isEmpty(), "a difference needs a why, and only a difference");
    check(c.expected, registerAll(r));
  }

  enum SignInCase {
    WHOLE("AAA", ""),
    WITH_USER_HANDLE("AAA", ""),
    USER_HANDLE_OTHER("RAR",
        "webauthn4j leaves comparing the user handle to the caller"),
    TYPE_CREATE("RRR", ""),
    CHALLENGE_OTHER("RRR", ""),
    ORIGIN_OTHER("RRR", ""),
    CROSS_ORIGIN("RRA",
        "Yubico does not check crossOrigin"),
    RP_ID_OTHER("RRR", ""),
    NO_USER_PRESENCE("RRR", ""),
    NO_USER_VERIFICATION("RRR", ""),
    BACKED_UP_NOT_ELIGIBLE("RRR", ""),
    BECAME_ELIGIBLE("RRR", ""),
    ATTESTED_DATA("RRA",
        "Yubico ignores attested credential data in a sign-in"),
    EXTENSIONS("AAA", ""),
    TRAILING_BYTE("RRA",
        "Yubico ignores bytes after the last part of a sign-in's authenticator data"),
    SIGNATURE_FLIPPED("RRR", ""),
    SIGNED_OTHER_FLAGS("RRR", ""),
    SIGNED_OTHER_CLIENT_DATA("RRR", ""),
    SIGNATURE_HIGH_S("AAA", ""),
    SIGNATURE_R_ZERO("RRR", ""),
    SIGNATURE_S_IS_ORDER("RRR", ""),
    SIGNATURE_PADDED_INTEGER("RRR", ""),
    SIGNATURE_LONG_FORM_LENGTH("RRR", ""),
    SIGNATURE_TRAILING_BYTE("RRR", ""),
    SIGNATURE_RAW_R_AND_S("RRR", ""),
    COUNTER_INCREASED("AAA", ""),
    COUNTER_SAME("RRR", ""),
    COUNTER_LOWER("RRR", ""),
    COUNTER_RESET_TO_ZERO("RRR", ""),
    COUNTER_BOTH_ZERO("AAA", "");

    final String expected;
    final String why;

    SignInCase(String expected, String why) {
      this.expected = expected;
      this.why = why;
    }

    long stored() {
      return switch (this) {
        case COUNTER_INCREASED, COUNTER_SAME, COUNTER_LOWER, COUNTER_RESET_TO_ZERO -> 5;
        default -> 0;
      };
    }

    void change(Assertion a) {
      switch (this) {
        case WHOLE, COUNTER_BOTH_ZERO -> { }
        case WITH_USER_HANDLE -> a.userHandle = USER;
        case USER_HANDLE_OTHER -> a.userHandle = "user-2".getBytes(StandardCharsets.UTF_8);
        case TYPE_CREATE -> a.clientData.type = "webauthn.create";
        case CHALLENGE_OTHER -> a.clientData.challenge = TestAuthenticator.b64(new byte[32]);
        case ORIGIN_OTHER -> a.clientData.origin = "https://evil.example";
        case CROSS_ORIGIN -> a.clientData.crossOrigin = true;
        case RP_ID_OTHER -> a.rpIdHash = TestAuthenticator.sha256("evil.example".getBytes(StandardCharsets.UTF_8));
        case NO_USER_PRESENCE -> a.flags &= ~UP;
        case NO_USER_VERIFICATION -> a.flags &= ~UV;
        case BACKED_UP_NOT_ELIGIBLE -> a.flags |= BS;
        case BECAME_ELIGIBLE -> a.flags |= BE;
        case ATTESTED_DATA -> {
          a.flags |= AT;
          byte[] header = new byte[18];
          header[17] = 1;
          a.attested = Oracles.concat(Oracles.concat(header, new byte[] {7}), TestCbor.encode(TestAuthenticator.coseKey(a.kind, a.keys)));
        }
        case EXTENSIONS -> {
          a.flags |= ED;
          a.extensions = TestCbor.encode(Map.of("devicePubKey", new byte[] {1}));
        }
        case TRAILING_BYTE -> a.trailing = new byte[] {0};
        case SIGNATURE_FLIPPED -> a.signatureChange = s -> {
          byte[] t = s.clone();
          t[t.length - 1] ^= 1;
          return t;
        };
        case SIGNED_OTHER_FLAGS -> a.afterSigning = b -> {
          byte[] t = b.clone();
          t[32] |= (byte) 0x20;
          return t;
        };
        case SIGNED_OTHER_CLIENT_DATA -> a.clientDataAfterSigning = b -> new String(b, StandardCharsets.UTF_8)
            .replace("}", ",\"x\":1}").getBytes(StandardCharsets.UTF_8);
        case SIGNATURE_HIGH_S -> a.signatureChange = s -> Der.der(Der.r(s), Der.N.subtract(Der.s(s)));
        case SIGNATURE_R_ZERO -> a.signatureChange = s -> Der.der(BigInteger.ZERO, Der.s(s));
        case SIGNATURE_S_IS_ORDER -> a.signatureChange = s -> Der.der(Der.r(s), Der.N);
        case SIGNATURE_PADDED_INTEGER -> a.signatureChange = s -> Der.derPadded(Der.r(s), Der.s(s));
        case SIGNATURE_LONG_FORM_LENGTH -> a.signatureChange = s -> Oracles.concat(new byte[] {0x30, (byte) 0x81, s[1]}, Arrays.copyOfRange(s, 2, s.length));
        case SIGNATURE_TRAILING_BYTE -> a.signatureChange = s -> Oracles.concat(s, new byte[] {0});
        case SIGNATURE_RAW_R_AND_S -> a.signatureChange = s -> Oracles.concat(TestAuthenticator.fixed(Der.r(s), 32), TestAuthenticator.fixed(Der.s(s), 32));
        case COUNTER_INCREASED -> a.signCount = 6;
        case COUNTER_SAME -> a.signCount = 5;
        case COUNTER_LOWER -> a.signCount = 4;
        case COUNTER_RESET_TO_ZERO -> a.signCount = 0;
      }
    }
  }

  @ParameterizedTest
  @EnumSource
  void signIn(SignInCase c) {
    Random random = new Random(c.name().hashCode());
    Registration r = new Registration(Kind.ES256, random);
    r.signCount = c.stored();
    Oracles.Stored stored = store(r);
    Assertion a = new Assertion(r, random);
    a.signCount = c.stored();
    c.change(a);
    assertEquals(c.expected.equals("AAA") || c.expected.equals("RRR"), c.why.isEmpty(), "a difference needs a why, and only a difference");
    check(c.expected, Oracles.signIn(stored, a.build(), a.challenge));
  }

  static Verdicts registerAll(Registration r) {
    var response = r.build();
    return Oracles.register(response.clientDataJson(), response.attestationObject(), r.challenge, USER, r.credentialId);
  }

  static Oracles.Stored store(Registration r) {
    var response = r.build();
    return Oracles.store(response.clientDataJson(), response.attestationObject(), r.challenge, USER, r.credentialId, r.signCount);
  }

  static void check(String expected, Verdicts v) {
    String actual = (v.ours().accepted() ? "A" : "R") + (v.webauthn4j().accepted() ? "A" : "R") + (v.yubico().accepted() ? "A" : "R");
    assertEquals(false, v.oursLooser(), () -> "Accepted by us and refused by an oracle:\n  " + v.summary());
    assertEquals(expected, actual, () -> v.summary());
  }

  /// ECDSA signatures in DER, taken apart and put together.
  static final class Der {
    static final BigInteger N = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);

    static BigInteger r(byte[] der) {
      return new BigInteger(1, Arrays.copyOfRange(der, 4, 4 + der[3]));
    }

    static BigInteger s(byte[] der) {
      int rl = der[3];
      return new BigInteger(1, Arrays.copyOfRange(der, 6 + rl, 6 + rl + der[5 + rl]));
    }

    static byte[] der(BigInteger r, BigInteger s) {
      byte[] rb = r.toByteArray();
      byte[] sb = s.toByteArray();
      byte[] body = Oracles.concat(Oracles.concat(new byte[] {0x02, (byte) rb.length}, rb), Oracles.concat(new byte[] {0x02, (byte) sb.length}, sb));
      return Oracles.concat(new byte[] {0x30, (byte) body.length}, body);
    }

    static byte[] derPadded(BigInteger r, BigInteger s) {
      byte[] rb = Oracles.concat(new byte[] {0}, r.toByteArray());
      if (rb.length > 1 && rb[1] == 0) {
        rb = Oracles.concat(new byte[] {0}, rb);
      }
      byte[] sb = s.toByteArray();
      byte[] body = Oracles.concat(Oracles.concat(new byte[] {0x02, (byte) rb.length}, rb), Oracles.concat(new byte[] {0x02, (byte) sb.length}, sb));
      return Oracles.concat(new byte[] {0x30, (byte) body.length}, body);
    }
  }
}
