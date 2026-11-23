package com.snaphop.webauthn;

import static com.snaphop.webauthn.TestAuthenticator.AT;
import static com.snaphop.webauthn.TestAuthenticator.BE;
import static com.snaphop.webauthn.TestAuthenticator.BS;
import static com.snaphop.webauthn.TestAuthenticator.ED;
import static com.snaphop.webauthn.TestAuthenticator.UP;
import static com.snaphop.webauthn.TestAuthenticator.UV;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.snaphop.webauthn.TestAuthenticator.Assertion;
import com.snaphop.webauthn.TestAuthenticator.Kind;
import com.snaphop.webauthn.TestAuthenticator.Registration;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/// Real ceremonies from [TestAuthenticator], whole and changed one part at a
/// time: each change must be refused for its reason, with its message.
class CeremonyTest {

  static final byte[] USER = "user-1".getBytes(StandardCharsets.UTF_8);

  static WebauthnRelyingParty.Builder rp() {
    return WebauthnRelyingParty.builder().id(TestAuthenticator.RP_ID).origin(TestAuthenticator.ORIGIN);
  }

  static final WebauthnRelyingParty RP = rp().build();
  static final WebauthnRelyingParty EVERY_ALGORITHM = rp().algorithms(WebauthnAlgorithm.values()).build();

  @ParameterizedTest
  @EnumSource
  void everyKind(Kind kind) {
    Random random = new Random(kind.name().hashCode());
    Registration r = new Registration(kind, random);
    r.flags |= BE | BS;
    r.signCount = 7;
    WebauthnCredential c = EVERY_ALGORITHM.register(r.build(), r.challenge, USER);
    assertEquals(kind.algorithm, c.algorithm());
    assertArrayEquals(r.credentialId, c.credentialId());
    assertArrayEquals(r.publicKeyCose(), c.publicKeyCose());
    assertArrayEquals(USER, c.userHandle());
    assertEquals(7, c.signCount());
    assertEquals(true, c.backupEligible());
    assertEquals(true, c.backedUp());
    assertEquals(new UUID(0, 0), c.aaguid());
    assertEquals("none", c.attestationFormat());

    Assertion a = new Assertion(r, random);
    a.flags |= BE;
    a.signCount = 8;
    a.userHandle = USER;
    WebauthnSignIn signIn = EVERY_ALGORITHM.signIn(a.build(), a.challenge, c);
    assertEquals(WebauthnSignIn.SignCount.INCREASED, signIn.signCount());
    assertEquals(true, signIn.userVerified());
    assertEquals(8, signIn.credential().signCount());
    assertEquals(false, signIn.credential().backedUp());
    assertEquals(true, signIn.credential().backupEligible());

    // The credential stored and read back works the same.
    WebauthnCredential stored = WebauthnCredential.builder(c.credentialId(), c.publicKeyCose(), c.userHandle())
        .signCount(signIn.credential().signCount())
        .backupEligible(true)
        .build();
    assertEquals(signIn.credential(), stored);
    Assertion again = new Assertion(r, random);
    again.flags |= BE;
    again.signCount = 9;
    assertEquals(9, EVERY_ALGORITHM.signIn(again.build(), again.challenge, stored).credential().signCount());
  }

  /// What a change to a registration does. `OK` when it is accepted.
  enum RegistrationCase {
    WHOLE("OK"),
    TYPE_GET("TYPE: The client data's type is \"webauthn.get\", not \"webauthn.create\""),
    CHALLENGE_OTHER("CHALLENGE: The client data's challenge is not the one given"),
    CHALLENGE_PADDED("CHALLENGE: The client data's challenge is not the one given"),
    CHALLENGE_STANDARD_BASE64("CHALLENGE: The client data's challenge is not the one given"),
    ORIGIN_OTHER("ORIGIN: The origin \"https://evil.example\" is not one of this relying party's: https://example.org"),
    ORIGIN_SLASH("ORIGIN: The origin \"https://example.org/\" is not one of this relying party's: https://example.org"),
    ORIGIN_HTTP("ORIGIN: The origin \"http://example.org\" is not one of this relying party's: https://example.org"),
    ORIGIN_UPPER_CASE("ORIGIN: The origin \"https://EXAMPLE.org\" is not one of this relying party's: https://example.org"),
    CROSS_ORIGIN("CROSS_ORIGIN: The response came from a frame of another origin (crossOrigin is true)"),
    CROSS_ORIGIN_ABSENT("OK"),
    CROSS_ORIGIN_NOT_BOOLEAN("CLIENT_DATA: The client data's \"crossOrigin\" is not true or false"),
    TOP_ORIGIN_WITHOUT_CROSS_ORIGIN("CROSS_ORIGIN: The client data has a topOrigin, \"https://example.com\", but crossOrigin is not true"),
    ORIGIN_TWICE("CLIENT_DATA: The client data is not JSON at character 135: the member \"origin\" is there twice"),
    EXTRA_MEMBERS("OK"),
    CLIENT_DATA_NOT_JSON("CLIENT_DATA: The client data is not JSON at character 0: unexpected 'x'"),
    CLIENT_DATA_TRAILING("CLIENT_DATA: The client data is not JSON at character 135: text after the JSON value"),
    CLIENT_DATA_NOT_UTF8("CLIENT_DATA: The client data is not UTF-8"),
    CLIENT_DATA_ARRAY("CLIENT_DATA: The client data is not a JSON object"),
    RP_ID_OTHER("RP_ID: The authenticator data is for another RP ID than \"example.org\""),
    NO_USER_PRESENCE("USER_PRESENCE: The user-present flag (UP) is not set"),
    NO_USER_VERIFICATION("USER_VERIFICATION: User verification is required, and the user-verified flag (UV) is not set"),
    BACKED_UP_NOT_ELIGIBLE("BACKUP: The backed-up flag (BS) is set without the backup-eligible flag (BE)"),
    NO_ATTESTED_DATA("AUTHENTICATOR_DATA: The authenticator data has no attested credential data (the AT flag is not set)"),
    AUTHENTICATOR_DATA_SHORT("AUTHENTICATOR_DATA: The authenticator data is 36 bytes, shorter than the 37 it must have"),
    AUTHENTICATOR_DATA_CUT_IN_AAGUID("AUTHENTICATOR_DATA: The authenticator data ends inside its attested credential data"),
    CREDENTIAL_ID_PAST_END("AUTHENTICATOR_DATA: The authenticator data's credential ID of 16 bytes runs past its end"),
    TRAILING_BYTE("AUTHENTICATOR_DATA: The authenticator data has 1 byte after its last part (the ED flag is not set)"),
    EXTENSIONS("OK"),
    EXTENSIONS_WITHOUT_FLAG("AUTHENTICATOR_DATA: The authenticator data has 14 bytes after its last part (the ED flag is not set)"),
    FLAG_WITHOUT_EXTENSIONS("AUTHENTICATOR_DATA: The authenticator data's ED flag is set, but it has no extensions"),
    EXTENSIONS_NOT_MAP("AUTHENTICATOR_DATA: The authenticator data's extensions are not a CBOR map"),
    EXTENSIONS_NOT_CBOR("AUTHENTICATOR_DATA: The authenticator data's extensions are not CBOR: Not well-formed CBOR at byte 148: additional information 28 is reserved (major type 5)"),
    FORMAT_PACKED("ATTESTATION: The attestation format \"packed\" is not \"none\", the only one this relying party accepts"),
    NONE_WITH_STATEMENT("ATTESTATION: The \"none\" attestation statement is not empty: {\"sig\": h'00'}"),
    NO_FORMAT("AUTHENTICATOR_DATA: The attestation object has no \"fmt\" text string"),
    FORMAT_NOT_TEXT("AUTHENTICATOR_DATA: The attestation object has no \"fmt\" text string"),
    STATEMENT_NOT_MAP("AUTHENTICATOR_DATA: The attestation object has no \"attStmt\" map"),
    AUTH_DATA_NOT_BYTES("AUTHENTICATOR_DATA: The attestation object has no \"authData\" byte string"),
    ATTESTATION_OBJECT_NOT_CBOR("AUTHENTICATOR_DATA: The attestation object is not CBOR: Not well-formed CBOR at byte 0: a map of 3 entries, but only 0 bytes are left"),
    ATTESTATION_OBJECT_NOT_MAP("AUTHENTICATOR_DATA: The attestation object is not a CBOR map"),
    ATTESTATION_OBJECT_DUPLICATE("AUTHENTICATOR_DATA: The attestation object is not CBOR: Not valid CBOR at byte 10: the key \"fmt\" is in the map twice"),
    CREDENTIAL_ID_EMPTY("CREDENTIAL_ID: A credential ID must be 1 to 1023 bytes: it is 0"),
    CREDENTIAL_ID_1023("OK"),
    CREDENTIAL_ID_1024("CREDENTIAL_ID: A credential ID must be 1 to 1023 bytes: it is 1024"),
    ALGORITHM_NOT_ALLOWED("PUBLIC_KEY: The credential's algorithm ES384 is not one this relying party allows: ES256, EDDSA, RS256"),
    COSE_ALGORITHM_FOR_OTHER_CURVE("PUBLIC_KEY: The credential public key's algorithm ES384 does not go with its curve P256 (ES256 does)"),
    COSE_UNKNOWN_ALGORITHM("PUBLIC_KEY: The credential public key's algorithm -65535 is not one this library checks"),
    COSE_NO_ALGORITHM("PUBLIC_KEY: The credential public key has no alg (3)"),
    COSE_ALGORITHM_NOT_INTEGER("PUBLIC_KEY: The credential public key's alg (3) is not an integer: \"ES256\""),
    COSE_ALGORITHM_HUGE("PUBLIC_KEY: The credential public key's alg (3) is out of range: -18446744073709551616"),
    COSE_UNKNOWN_KEY_TYPE("PUBLIC_KEY: The credential public key's key type 4 is not one this library reads (1 OKP, 2 EC2, 3 RSA)"),
    COSE_UNKNOWN_CURVE("PUBLIC_KEY: The credential public key's EC2 curve 4 is not one this library reads (1 P-256, 2 P-384, 3 P-521)"),
    COSE_POINT_NOT_ON_CURVE("PUBLIC_KEY: The credential public key's point is not on P256"),
    COSE_COORDINATE_ABOVE_PRIME("PUBLIC_KEY: The credential public key's coordinates are not less than P256's prime"),
    COSE_COORDINATE_SHORT("PUBLIC_KEY: The credential public key's coordinates must be 32 bytes for P256: x is 31, y is 32"),
    COSE_COORDINATE_NOT_BYTES("PUBLIC_KEY: The credential public key's y (-3) is not a byte string"),
    COSE_NO_Y("PUBLIC_KEY: The credential public key has no y (-3)"),
    COSE_EXTRA_MEMBER("OK"),
    COSE_NOT_MAP("PUBLIC_KEY: The credential public key is not a COSE key (a CBOR map): CborArray"),
    COSE_DUPLICATE_MEMBER("AUTHENTICATOR_DATA: The authenticator data's credential public key is not CBOR: Not valid CBOR at byte 148: the key 1 is in the map twice"),
    COSE_NOT_CBOR("AUTHENTICATOR_DATA: The authenticator data's credential public key is not CBOR: Not well-formed CBOR at byte 71: additional information 28 is reserved (major type 7)");

    final String expected;

    RegistrationCase(String expected) {
      this.expected = expected;
    }

    void change(Registration r) {
      switch (this) {
        case WHOLE -> { }
        case CROSS_ORIGIN_ABSENT -> r.clientData.crossOrigin = null;
        case TYPE_GET -> r.clientData.type = "webauthn.get";
        case CHALLENGE_OTHER -> r.clientData.challenge = TestAuthenticator.b64(new byte[32]);
        case CHALLENGE_PADDED -> r.clientData.challenge += "=";
        case CHALLENGE_STANDARD_BASE64 -> r.clientData.challenge = java.util.Base64.getEncoder().encodeToString(r.challenge);
        case ORIGIN_OTHER -> r.clientData.origin = "https://evil.example";
        case ORIGIN_SLASH -> r.clientData.origin = "https://example.org/";
        case ORIGIN_HTTP -> r.clientData.origin = "http://example.org";
        case ORIGIN_UPPER_CASE -> r.clientData.origin = "https://EXAMPLE.org";
        case CROSS_ORIGIN -> r.clientData.crossOrigin = true;
        case CROSS_ORIGIN_NOT_BOOLEAN -> {
          r.clientData.crossOrigin = null;
          r.clientData.extra = ",\"crossOrigin\":\"false\"";
        }
        case TOP_ORIGIN_WITHOUT_CROSS_ORIGIN -> r.clientData.topOrigin = "https://example.com";
        case ORIGIN_TWICE -> r.clientData.extra = ",\"origin\":\"https://evil.example\"";
        case EXTRA_MEMBERS -> r.clientData.extra = ",\"other_keys_can_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\",\"tokenBinding\":{\"status\":\"supported\"},\"n\":[1.5e3,-0,{}]";
        case CLIENT_DATA_NOT_JSON -> r.clientDataChange = b -> "x".getBytes(StandardCharsets.UTF_8);
        case CLIENT_DATA_TRAILING -> r.clientDataChange = b -> concat(b, "x".getBytes(StandardCharsets.UTF_8));
        case CLIENT_DATA_NOT_UTF8 -> r.clientDataChange = b -> concat(b, new byte[] {(byte) 0xc3});
        case CLIENT_DATA_ARRAY -> r.clientDataChange = b -> concat(concat(new byte[] {'['}, b), new byte[] {']'});
        case RP_ID_OTHER -> r.rpIdHash = TestAuthenticator.sha256("evil.example".getBytes(StandardCharsets.UTF_8));
        case NO_USER_PRESENCE -> r.flags &= ~UP;
        case NO_USER_VERIFICATION -> r.flags &= ~UV;
        case BACKED_UP_NOT_ELIGIBLE -> r.flags |= BS;
        case NO_ATTESTED_DATA -> r.flags &= ~AT;
        case AUTHENTICATOR_DATA_SHORT -> r.authenticatorDataChange = b -> Arrays.copyOf(b, 36);
        case AUTHENTICATOR_DATA_CUT_IN_AAGUID -> r.authenticatorDataChange = b -> Arrays.copyOf(b, 50);
        case CREDENTIAL_ID_PAST_END -> r.authenticatorDataChange = b -> Arrays.copyOf(b, 60);
        case TRAILING_BYTE -> r.trailing = new byte[] {0};
        case EXTENSIONS -> {
          r.flags |= ED;
          r.extensions = TestCbor.encode(Map.of("credProtect", 2));
        }
        case EXTENSIONS_WITHOUT_FLAG -> r.extensions = TestCbor.encode(Map.of("credProtect", 2));
        case FLAG_WITHOUT_EXTENSIONS -> r.flags |= ED;
        case EXTENSIONS_NOT_MAP -> {
          r.flags |= ED;
          r.extensions = TestCbor.encode(List.of(1));
        }
        case EXTENSIONS_NOT_CBOR -> {
          r.flags |= ED;
          r.extensions = new byte[] {(byte) 0xbc};
        }
        case FORMAT_PACKED -> r.fmt = "packed";
        case NONE_WITH_STATEMENT -> r.attStmt.put("sig", new byte[] {0});
        case NO_FORMAT -> r.attestationObjectChange = b -> TestCbor.encode(Map.of("attStmt", Map.of(), "authData", r.authenticatorData()));
        case FORMAT_NOT_TEXT -> r.attestationObjectChange = b -> withFmt(r, 1);
        case STATEMENT_NOT_MAP -> r.attestationObjectChange = b -> TestCbor.encode(ordered("fmt", "none", "attStmt", List.of(), "authData", r.authenticatorData()));
        case AUTH_DATA_NOT_BYTES -> r.attestationObjectChange = b -> TestCbor.encode(ordered("fmt", "none", "attStmt", Map.of(), "authData", "x"));
        case ATTESTATION_OBJECT_NOT_CBOR -> r.attestationObjectChange = b -> new byte[] {(byte) 0xa3};
        case ATTESTATION_OBJECT_NOT_MAP -> r.attestationObjectChange = b -> TestCbor.encode(List.of());
        case ATTESTATION_OBJECT_DUPLICATE -> r.attestationObjectChange = b -> concat(new byte[] {(byte) 0xa2},
            concat(concat(TestCbor.encode("fmt"), TestCbor.encode("none")), concat(TestCbor.encode("fmt"), TestCbor.encode("none"))));
        case CREDENTIAL_ID_EMPTY -> r.credentialId = new byte[0];
        case CREDENTIAL_ID_1023 -> r.credentialId = new byte[1023];
        case CREDENTIAL_ID_1024 -> r.credentialId = new byte[1024];
        case ALGORITHM_NOT_ALLOWED -> throw new IllegalStateException("made with ES384 instead");
        case COSE_ALGORITHM_FOR_OTHER_CURVE -> r.cose.put(3, -35);
        case COSE_UNKNOWN_ALGORITHM -> r.cose.put(3, -65535);
        case COSE_NO_ALGORITHM -> r.cose.remove(3);
        case COSE_ALGORITHM_NOT_INTEGER -> r.cose.put(3, "ES256");
        case COSE_ALGORITHM_HUGE -> r.cose.put(3, new TestCbor.Raw(HexFormat.of().parseHex("3bffffffffffffffff")));
        case COSE_UNKNOWN_KEY_TYPE -> r.cose.put(1, 4);
        case COSE_UNKNOWN_CURVE -> r.cose.put(-1, 4);
        case COSE_POINT_NOT_ON_CURVE -> {
          byte[] y = ((byte[]) java.util.Objects.requireNonNull(r.cose.get(-3))).clone();
          y[31] ^= 1;
          r.cose.put(-3, y);
        }
        case COSE_COORDINATE_ABOVE_PRIME -> {
          BigInteger p = ((java.security.spec.ECFieldFp) ((ECPublicKey) r.keys.getPublic()).getParams().getCurve().getField()).getP();
          r.cose.put(-2, TestAuthenticator.fixed(p, 32));
        }
        case COSE_COORDINATE_SHORT -> r.cose.put(-2, Arrays.copyOf((byte[]) java.util.Objects.requireNonNull(r.cose.get(-2)), 31));
        case COSE_COORDINATE_NOT_BYTES -> r.cose.put(-3, 0);
        case COSE_NO_Y -> r.cose.remove(-3);
        case COSE_EXTRA_MEMBER -> r.cose.put(2, new byte[] {1, 2, 3});
        case COSE_NOT_MAP -> r.coseBytes = TestCbor.encode(List.of(1, 2));
        case COSE_DUPLICATE_MEMBER -> r.coseBytes = concat(new byte[] {(byte) 0xa6}, concat(Arrays.copyOfRange(TestCbor.encode(r.cose), 1, TestCbor.encode(r.cose).length), new byte[] {0x01, 0x02}));
        case COSE_NOT_CBOR -> r.coseBytes = new byte[] {(byte) 0xfc};
      }
    }
  }

  @ParameterizedTest
  @EnumSource
  void registration(RegistrationCase c) {
    Random random = new Random(c.name().hashCode());
    Registration r = new Registration(c == RegistrationCase.ALGORITHM_NOT_ALLOWED ? Kind.ES384 : Kind.ES256, random);
    if (c != RegistrationCase.ALGORITHM_NOT_ALLOWED) {
      c.change(r);
    }
    outcome(c.expected, () -> RP.register(r.build(), r.challenge, USER));
  }

  @Test
  void crossOriginAllowed() {
    Random random = new Random(3);
    WebauthnRelyingParty framed = rp().crossOrigin(WebauthnRelyingParty.CrossOrigin.ALLOW).topOrigin("https://example.com").build();
    Registration r = new Registration(Kind.ES256, random);
    r.clientData.crossOrigin = true;
    framed.register(r.build(), r.challenge, USER);
    r.clientData.topOrigin = "https://example.com";
    framed.register(r.build(), r.challenge, USER);
    r.clientData.topOrigin = "https://evil.example";
    outcome("CROSS_ORIGIN: The top origin \"https://evil.example\" is not one this relying party may be framed in",
        () -> framed.register(r.build(), r.challenge, USER));
    r.clientData.crossOrigin = false;
    outcome("CROSS_ORIGIN: The client data has a topOrigin, \"https://evil.example\", but crossOrigin is not true",
        () -> framed.register(r.build(), r.challenge, USER));
  }

  @Test
  void attestationAnyUnverified() {
    Random random = new Random(4);
    WebauthnRelyingParty any = rp().attestation(WebauthnRelyingParty.Attestation.ANY_UNVERIFIED).build();
    Registration r = new Registration(Kind.ES256, random);
    r.fmt = "packed";
    r.attStmt.put("alg", -7);
    r.attStmt.put("sig", new byte[] {1});
    assertEquals("packed", any.register(r.build(), r.challenge, USER).attestationFormat());
    for (String format : List.of("tpm", "android-key", "android-safetynet", "fido-u2f", "apple", "compound")) {
      r.fmt = format;
      assertEquals(format, any.register(r.build(), r.challenge, USER).attestationFormat());
    }
    r.fmt = "nne";
    outcome("ATTESTATION: The attestation format \"nne\" is not one of WebAuthn's: packed, tpm, android-key, android-safetynet, fido-u2f, apple, compound, none",
        () -> any.register(r.build(), r.challenge, USER));
    Registration none = new Registration(Kind.ES256, random);
    none.attStmt.put("x", 1);
    outcome("ATTESTATION: The \"none\" attestation statement is not empty: {\"x\": 1}", () -> any.register(none.build(), none.challenge, USER));
  }

  @Test
  void userVerificationNotRequired() {
    Random random = new Random(5);
    for (WebauthnRelyingParty.UserVerification uv : List.of(WebauthnRelyingParty.UserVerification.PREFERRED, WebauthnRelyingParty.UserVerification.DISCOURAGED)) {
      WebauthnRelyingParty relaxed = rp().userVerification(uv).build();
      Registration r = new Registration(Kind.ES256, random);
      r.flags &= ~UV;
      WebauthnCredential c = relaxed.register(r.build(), r.challenge, USER);
      Assertion a = new Assertion(r, random);
      a.flags &= ~UV;
      assertEquals(false, relaxed.signIn(a.build(), a.challenge, c).userVerified());
    }
  }

  /// What a change to a sign-in does. `OK` when it is accepted.
  enum SignInCase {
    WHOLE("OK"),
    WITH_USER_HANDLE("OK"),
    USER_HANDLE_OTHER("USER_HANDLE: The response's user handle is not the one the credential was registered for"),
    CREDENTIAL_ID_OTHER("CREDENTIAL_ID: The response's credential ID is not the stored credential's"),
    TYPE_CREATE("TYPE: The client data's type is \"webauthn.create\", not \"webauthn.get\""),
    CHALLENGE_OTHER("CHALLENGE: The client data's challenge is not the one given"),
    ORIGIN_OTHER("ORIGIN: The origin \"https://evil.example\" is not one of this relying party's: https://example.org"),
    CROSS_ORIGIN("CROSS_ORIGIN: The response came from a frame of another origin (crossOrigin is true)"),
    RP_ID_OTHER("RP_ID: The authenticator data is for another RP ID than \"example.org\""),
    NO_USER_PRESENCE("USER_PRESENCE: The user-present flag (UP) is not set"),
    NO_USER_VERIFICATION("USER_VERIFICATION: User verification is required, and the user-verified flag (UV) is not set"),
    BACKED_UP_NOT_ELIGIBLE("BACKUP: The backed-up flag (BS) is set without the backup-eligible flag (BE)"),
    BECAME_ELIGIBLE("BACKUP: The credential was registered not backup eligible, and now says it is"),
    ATTESTED_DATA("AUTHENTICATOR_DATA: The authenticator data of a sign-in has attested credential data (the AT flag is set)"),
    EXTENSIONS("OK"),
    TRAILING_BYTE("AUTHENTICATOR_DATA: The authenticator data has 1 byte after its last part (the ED flag is not set)"),
    SHORT("AUTHENTICATOR_DATA: The authenticator data is 36 bytes, shorter than the 37 it must have"),
    SIGNATURE_FLIPPED("SIGNATURE: The signature does not verify with the credential's ES256 key"),
    SIGNATURE_EMPTY("SIGNATURE: The signature does not verify with the credential's ES256 key"),
    SIGNED_OTHER_FLAGS("SIGNATURE: The signature does not verify with the credential's ES256 key"),
    SIGNED_OTHER_CLIENT_DATA("SIGNATURE: The signature does not verify with the credential's ES256 key"),
    SIGNATURE_HIGH_S("OK"),
    SIGNATURE_R_ZERO("SIGNATURE: The signature does not verify with the credential's ES256 key"),
    SIGNATURE_S_IS_ORDER("SIGNATURE: The signature does not verify with the credential's ES256 key"),
    SIGNATURE_PADDED_INTEGER("SIGNATURE: The signature does not verify with the credential's ES256 key"),
    SIGNATURE_LONG_FORM_LENGTH("SIGNATURE: The signature does not verify with the credential's ES256 key"),
    SIGNATURE_TRAILING_BYTE("SIGNATURE: The signature does not verify with the credential's ES256 key"),
    SIGNATURE_RAW_R_AND_S("SIGNATURE: The signature does not verify with the credential's ES256 key"),
    COUNTER_INCREASED("OK INCREASED"),
    COUNTER_SAME("SIGN_COUNT: The signature counter is 5, not more than the 5 last seen: the authenticator may have been cloned"),
    COUNTER_LOWER("SIGN_COUNT: The signature counter is 4, not more than the 5 last seen: the authenticator may have been cloned"),
    COUNTER_RESET_TO_ZERO("SIGN_COUNT: The signature counter is 0, not more than the 5 last seen: the authenticator may have been cloned"),
    COUNTER_STARTS("OK INCREASED"),
    COUNTER_LARGEST("OK INCREASED");

    final String expected;

    SignInCase(String expected) {
      this.expected = expected;
    }

    long stored() {
      return switch (this) {
        case COUNTER_INCREASED, COUNTER_SAME, COUNTER_LOWER, COUNTER_RESET_TO_ZERO -> 5;
        default -> 0;
      };
    }

    void change(Assertion a) {
      switch (this) {
        case WHOLE -> { }
        case WITH_USER_HANDLE -> a.userHandle = USER;
        case USER_HANDLE_OTHER -> a.userHandle = "user-2".getBytes(StandardCharsets.UTF_8);
        case CREDENTIAL_ID_OTHER -> a.credentialId[0] ^= 1;
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
          // An AAGUID, a one-byte credential ID, and the key.
          byte[] header = new byte[18];
          header[17] = 1;
          a.attested = concat(concat(header, new byte[] {7}), TestCbor.encode(TestAuthenticator.coseKey(a.kind, a.keys)));
        }
        case EXTENSIONS -> {
          a.flags |= ED;
          a.extensions = TestCbor.encode(Map.of("devicePubKey", new byte[] {1}));
        }
        case TRAILING_BYTE -> a.trailing = new byte[] {0};
        case SHORT -> a.authenticatorDataChange = b -> Arrays.copyOf(b, 36);
        case SIGNATURE_FLIPPED -> a.signatureChange = s -> {
          byte[] t = s.clone();
          t[t.length - 1] ^= 1;
          return t;
        };
        case SIGNATURE_EMPTY -> a.signatureChange = s -> new byte[0];
        case SIGNED_OTHER_FLAGS -> a.afterSigning = b -> {
          byte[] t = b.clone();
          t[32] |= (byte) 0x20;
          return t;
        };
        case SIGNED_OTHER_CLIENT_DATA -> a.clientDataAfterSigning = b -> new String(b, StandardCharsets.UTF_8)
            .replace("}", ",\"x\":1}").getBytes(StandardCharsets.UTF_8);
        case SIGNATURE_HIGH_S -> a.signatureChange = s -> der(r(s), N.subtract(s(s)));
        case SIGNATURE_R_ZERO -> a.signatureChange = s -> der(BigInteger.ZERO, s(s));
        case SIGNATURE_S_IS_ORDER -> a.signatureChange = s -> der(r(s), N);
        case SIGNATURE_PADDED_INTEGER -> a.signatureChange = s -> derPadded(r(s), s(s));
        case SIGNATURE_LONG_FORM_LENGTH -> a.signatureChange = s -> concat(new byte[] {0x30, (byte) 0x81, s[1]}, Arrays.copyOfRange(s, 2, s.length));
        case SIGNATURE_TRAILING_BYTE -> a.signatureChange = s -> concat(s, new byte[] {0});
        case SIGNATURE_RAW_R_AND_S -> a.signatureChange = s -> concat(TestAuthenticator.fixed(r(s), 32), TestAuthenticator.fixed(s(s), 32));
        case COUNTER_INCREASED -> a.signCount = 6;
        case COUNTER_SAME -> a.signCount = 5;
        case COUNTER_LOWER -> a.signCount = 4;
        case COUNTER_RESET_TO_ZERO -> a.signCount = 0;
        case COUNTER_STARTS -> a.signCount = 1;
        case COUNTER_LARGEST -> a.signCount = 0xffff_ffffL;
      }
    }
  }

  static final BigInteger N = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);

  @ParameterizedTest
  @EnumSource
  void signIn(SignInCase c) {
    Random random = new Random(c.name().hashCode() + 1);
    Registration r = new Registration(Kind.ES256, random);
    r.signCount = c.stored();
    WebauthnCredential credential = RP.register(r.build(), r.challenge, USER);
    Assertion a = new Assertion(r, random);
    a.signCount = c.stored();
    c.change(a);
    WebauthnAssertion response = a.build();
    String outcome = outcome(c.expected.startsWith("OK") ? "OK" : c.expected, () -> RP.signIn(response, a.challenge, credential));
    if (c.expected.startsWith("OK ")) {
      assertEquals(c.expected.substring(3), outcome);
    }
  }

  @Test
  void signCountReported() {
    Random random = new Random(6);
    WebauthnRelyingParty report = rp().signCountCheck(WebauthnRelyingParty.SignCountCheck.REPORT).build();
    Registration r = new Registration(Kind.ES256, random);
    r.signCount = 5;
    WebauthnCredential c = report.register(r.build(), r.challenge, USER);
    Assertion a = new Assertion(r, random);
    a.signCount = 3;
    WebauthnSignIn signIn = report.signIn(a.build(), a.challenge, c);
    assertEquals(WebauthnSignIn.SignCount.NOT_INCREASED, signIn.signCount());
    // The highest seen is kept, so a clone stays behind.
    assertEquals(5, signIn.credential().signCount());
    Assertion zero = new Assertion(r, random);
    WebauthnCredential z = report.register(r.build(), r.challenge, USER);
    assertEquals(WebauthnSignIn.SignCount.NOT_INCREASED, report.signIn(zero.build(), zero.challenge, z).signCount());
  }

  @Test
  void builders() {
    assertEquals("A relying party needs an RP ID: id(\"example.org\")",
        assertThrows(IllegalStateException.class, () -> WebauthnRelyingParty.builder().origin("https://a").build()).getMessage());
    assertEquals("A relying party needs an RP ID: id(\"example.org\")",
        assertThrows(IllegalStateException.class, () -> WebauthnRelyingParty.builder().id("").origin("https://a").build()).getMessage());
    assertEquals("A relying party needs at least one origin: origin(\"https://a.example\")",
        assertThrows(IllegalStateException.class, () -> WebauthnRelyingParty.builder().id("a.example").build()).getMessage());
    assertEquals("At least one algorithm is needed",
        assertThrows(IllegalArgumentException.class, () -> WebauthnRelyingParty.builder().algorithms()).getMessage());
    assertEquals("example.org", RP.id());

    Registration r = new Registration(Kind.ES256, new Random(7));
    WebauthnRegistration response = r.build();
    assertEquals("A user handle must be 1 to 64 bytes: 0",
        assertThrows(IllegalArgumentException.class, () -> RP.register(response, r.challenge, new byte[0])).getMessage());
    assertEquals("A user handle must be 1 to 64 bytes: 65",
        assertThrows(IllegalArgumentException.class, () -> RP.register(response, r.challenge, new byte[65])).getMessage());
    RP.register(response, r.challenge, new byte[64]);

    byte[] cose = r.publicKeyCose();
    assertEquals("A user handle must be 1 to 64 bytes: 0",
        assertThrows(IllegalArgumentException.class, () -> WebauthnCredential.builder(new byte[1], cose, new byte[0]).build()).getMessage());
    assertEquals("A user handle must be 1 to 64 bytes: 65",
        assertThrows(IllegalArgumentException.class, () -> WebauthnCredential.builder(new byte[1], cose, new byte[65]).build()).getMessage());
    outcome("CREDENTIAL_ID: A credential ID must be 1 to 1023 bytes: it is 0", () -> WebauthnCredential.builder(new byte[0], cose, USER).build());
    outcome("BACKUP: A credential can't be backed up without being backup eligible", () -> WebauthnCredential.builder(new byte[1], cose, USER).backedUp(true).build());
    outcome("PUBLIC_KEY: The credential public key is not CBOR: Not well-formed CBOR at byte 0: the input ends before an item",
        () -> WebauthnCredential.builder(new byte[1], new byte[0], USER).build());
    assertEquals("signCount must be 0 to 2^32 - 1: -1",
        assertThrows(IllegalArgumentException.class, () -> WebauthnCredential.builder(new byte[1], cose, USER).signCount(-1)).getMessage());
    assertEquals("signCount must be 0 to 2^32 - 1: 4294967296",
        assertThrows(IllegalArgumentException.class, () -> WebauthnCredential.builder(new byte[1], cose, USER).signCount(0x1_0000_0000L)).getMessage());
    WebauthnCredential c = WebauthnCredential.builder(new byte[] {1, 2}, cose, USER)
        .signCount(0xffff_ffffL).backupEligible(true).backedUp(true)
        .aaguid(new UUID(1, 2)).attestationFormat("packed").build();
    assertEquals("WebauthnCredential[ES256, 2-byte ID, signCount 4294967295, backup eligible, backed up]", c.toString());
    assertEquals(new UUID(1, 2), c.aaguid());
    assertEquals("packed", c.attestationFormat());
    assertEquals(false, c.equals(WebauthnCredential.builder(new byte[] {1, 2}, cose, USER).build()));
    assertEquals(c.hashCode(), WebauthnCredential.builder(new byte[] {1, 2}, cose, USER).build().hashCode());

    // Inputs and outputs are copies.
    byte[] id = {1, 2};
    WebauthnCredential copied = WebauthnCredential.builder(id, cose, USER).build();
    id[0] = 9;
    copied.credentialId()[1] = 9;
    assertArrayEquals(new byte[] {1, 2}, copied.credentialId());
    WebauthnAssertion assertion = WebauthnAssertion.builder().credentialId(id).clientDataJson(id).authenticatorData(id).signature(id).build();
    assertEquals(null, assertion.userHandleOrNull());
    assertArrayEquals(id, assertion.signature());
    assertArrayEquals(id, assertion.authenticatorData());
    assertArrayEquals(id, assertion.clientDataJson());
    assertArrayEquals(id, assertion.credentialId());
    assertEquals("credentialId", assertThrows(NullPointerException.class, () -> WebauthnAssertion.builder().build()).getMessage());
    assertArrayEquals(response.clientDataJson(), r.build().clientDataJson());
    assertArrayEquals(response.attestationObject(), r.build().attestationObject());
  }

  @Test
  void algorithms() {
    for (WebauthnAlgorithm a : WebauthnAlgorithm.values()) {
      assertEquals(a, WebauthnAlgorithm.ofCoseIdOrNull(a.coseId()));
    }
    assertEquals(null, WebauthnAlgorithm.ofCoseIdOrNull(-65535));
    assertEquals(List.of(-7, -35, -36, -8, -19, -53, -257, -37), Arrays.stream(WebauthnAlgorithm.values()).map(WebauthnAlgorithm::coseId).toList());
  }

  static String outcome(String expected, java.util.function.Supplier<?> ceremony) {
    if (expected.equals("OK")) {
      Object result = ceremony.get();
      return result instanceof WebauthnSignIn s ? s.signCount().name() : "OK";
    }
    WebauthnException e = assertThrows(WebauthnException.class, ceremony::get);
    assertEquals(expected, e.reason() + ": " + e.getMessage());
    return expected;
  }

  static byte[] concat(byte[] a, byte[] b) {
    byte[] out = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  static Map<Object, Object> ordered(Object... keysAndValues) {
    Map<Object, Object> m = new java.util.LinkedHashMap<>();
    for (int i = 0; i < keysAndValues.length; i += 2) {
      m.put(keysAndValues[i], keysAndValues[i + 1]);
    }
    return m;
  }

  static byte[] withFmt(Registration r, Object fmt) {
    return TestCbor.encode(ordered("fmt", fmt, "attStmt", Map.of(), "authData", r.authenticatorData()));
  }

  static BigInteger r(byte[] der) {
    int rl = der[3];
    return new BigInteger(1, Arrays.copyOfRange(der, 4, 4 + rl));
  }

  static BigInteger s(byte[] der) {
    int rl = der[3];
    int sl = der[5 + rl];
    return new BigInteger(1, Arrays.copyOfRange(der, 6 + rl, 6 + rl + sl));
  }

  static byte[] der(BigInteger r, BigInteger s) {
    byte[] rb = r.toByteArray();
    byte[] sb = s.toByteArray();
    byte[] body = concat(concat(new byte[] {0x02, (byte) rb.length}, rb), concat(new byte[] {0x02, (byte) sb.length}, sb));
    return concat(new byte[] {0x30, (byte) body.length}, body);
  }

  static byte[] derPadded(BigInteger r, BigInteger s) {
    byte[] rb = concat(new byte[] {0}, r.toByteArray());
    if (rb.length > 1 && rb[1] == 0) {
      rb = concat(new byte[] {0}, rb);
    }
    byte[] sb = s.toByteArray();
    byte[] body = concat(concat(new byte[] {0x02, (byte) rb.length}, rb), concat(new byte[] {0x02, (byte) sb.length}, sb));
    return concat(new byte[] {0x30, (byte) body.length}, body);
  }
}
