package com.snaphop.webauthn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.snaphop.webauthn.TestAuthenticator.Kind;
import com.snaphop.webauthn.TestAuthenticator.Registration;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/// The parts a ceremony can't reach on its own: the DER check (the JDK
/// refuses the same signatures, so a ceremony can't tell whether ours ran;
/// it is there for the day the JDK lets one through, as CVE-2022-21449
/// did), the client data's JSON grammar and messages, COSE keys the test
/// authenticator wouldn't make, and lengths at their edges.
class PartsTest {

  static final BigInteger N = CeremonyTest.N;

  /// DER signatures, and whether the strict check takes them. `r` is 5 and
  /// `s` is 7 unless said.
  enum Der {
    MINIMAL("3006020105020107", true),
    R_HIGH_BIT_PADDED("300702020080020107", true),
    LONG_FORM_SEQUENCE("308106020105020107", false),
    LONG_FORM_INTEGER("30070281010502010" + "7", false),
    INDEFINITE_LENGTH("3080020105020107" + "0000", false),
    LENGTH_IN_THREE_BYTES("30830000060201050201" + "07", false),
    TWO_BYTE_LENGTH_LEADING_ZERO("3082000602010502010" + "7", false),
    SEQUENCE_TOO_LONG("3007020105020107", false),
    SEQUENCE_TOO_SHORT("3005020105020107", false),
    TRAILING_BYTE("300602010502010700", false),
    NOT_A_SEQUENCE("3106020105020107", false),
    R_NOT_INTEGER("3006030105020107", false),
    S_NOT_INTEGER("3006020105030107", false),
    R_ZERO_LENGTH("30050200020107", false),
    R_NEGATIVE("3006020185020107", false),
    R_PADDED("300702020005020107", false),
    R_ZERO("3006020100020107", false),
    S_ZERO("3006020105020100", false),
    S_MISSING("3003020105", false),
    EMPTY("", false),
    ONLY_TAG("30", false),
    R_RUNS_PAST_END("3006020905020107", false);

    final String hex;
    final boolean strict;

    Der(String hex, boolean strict) {
      this.hex = hex;
      this.strict = strict;
    }
  }

  @ParameterizedTest
  @EnumSource
  void der(Der d) {
    assertEquals(d.strict, Signatures.strictDer(HexFormat.of().parseHex(d.hex), N), d.hex);
  }

  @Test
  void derRange() {
    BigInteger nMinus1 = N.subtract(BigInteger.ONE);
    assertEquals(true, Signatures.strictDer(CeremonyTest.der(nMinus1, nMinus1), N));
    assertEquals(false, Signatures.strictDer(CeremonyTest.der(N, BigInteger.ONE), N));
    assertEquals(false, Signatures.strictDer(CeremonyTest.der(BigInteger.ONE, N), N));
    assertEquals(true, Signatures.strictDer(CeremonyTest.der(BigInteger.ONE, BigInteger.ONE), N));
    // A long-form length that is needed: 138 bytes of r. 126 bytes would
    // fit the short form, so its long form is refused.
    BigInteger big = BigInteger.ONE.shiftLeft(1100);
    byte[] r = big.toByteArray();
    byte[] body = CeremonyTest.concat(CeremonyTest.concat(new byte[] {0x02, (byte) 0x81, (byte) r.length}, r), new byte[] {0x02, 0x01, 0x07});
    byte[] sig = CeremonyTest.concat(new byte[] {0x30, (byte) 0x81, (byte) body.length}, body);
    assertEquals(true, Signatures.strictDer(sig, big.add(BigInteger.ONE)));
    assertEquals(false, Signatures.strictDer(sig, N));
    byte[] small = BigInteger.ONE.shiftLeft(1000).toByteArray();
    byte[] bodyShort = CeremonyTest.concat(CeremonyTest.concat(new byte[] {0x02, (byte) 0x81, (byte) small.length}, small), new byte[] {0x02, 0x01, 0x07});
    assertEquals(126, small.length);
    assertEquals(false, Signatures.strictDer(CeremonyTest.concat(new byte[] {0x30, (byte) 0x81, (byte) bodyShort.length}, bodyShort), big));
    byte[] body2 = CeremonyTest.concat(CeremonyTest.concat(new byte[] {0x02, (byte) 0x82, 0x00, (byte) r.length}, r), new byte[] {0x02, 0x01, 0x07});
    assertEquals(false, Signatures.strictDer(CeremonyTest.concat(new byte[] {0x30, (byte) 0x81, (byte) body2.length}, body2), big.add(BigInteger.ONE)));
    byte[] body3 = CeremonyTest.concat(CeremonyTest.concat(new byte[] {0x02, (byte) 0x82, 0x01, 0x00}, new byte[256]), new byte[0]);
    body3[4] = 1;
    byte[] sig3 = CeremonyTest.concat(CeremonyTest.concat(new byte[] {0x30, (byte) 0x82, 0x01, 0x07}, body3), new byte[] {0x02, 0x01, 0x07});
    assertEquals(true, Signatures.strictDer(sig3, BigInteger.ONE.shiftLeft(2100)));
  }

  /// Client data, and what it reads as: `!` and the message when refused,
  /// otherwise the challenge it has.
  enum ClientJson {
    SPACES_EVERYWHERE(" \t\n\r{ \"type\" : \"t\" , \"challenge\" : \"c\" , \"origin\" : \"o\" } \r\n", "c"),
    ESCAPES("{\"type\":\"t\",\"challenge\":\"\\u0063\\\"\\\\\\/\\b\\f\\n\\r\\t\",\"origin\":\"o\"}", "c\"\\/\b\f\n\r\t"),
    SURROGATE_PAIR("{\"type\":\"t\",\"challenge\":\"\\ud83d\\ude00\",\"origin\":\"o\"}", "\ud83d\ude00"),
    NESTED_VALUES("{\"type\":\"t\",\"x\":[1,-0.5e+3,2E-1,true,false,null,[],{},{\"a\":[[]]}],\"challenge\":\"c\",\"origin\":\"o\"}", "c"),
    EMPTY_ARRAY_WITH_SPACE("{\"x\":[ ],\"y\":{ },\"type\":\"t\",\"challenge\":\"c\",\"origin\":\"o\"}", "c"),
    CROSS_ORIGIN_FALSE("{\"type\":\"t\",\"challenge\":\"c\",\"origin\":\"o\",\"crossOrigin\":false}", "c"),
    NO_TYPE("{\"challenge\":\"c\",\"origin\":\"o\"}", "!The client data has no \"type\""),
    NO_ORIGIN("{\"type\":\"t\",\"challenge\":\"c\"}", "!The client data has no \"origin\""),
    CHALLENGE_NULL("{\"type\":\"t\",\"challenge\":null,\"origin\":\"o\"}", "!The client data's \"challenge\" is not a string"),
    CHALLENGE_NUMBER("{\"type\":\"t\",\"challenge\":1,\"origin\":\"o\"}", "!The client data's \"challenge\" is not a string"),
    TOP_ORIGIN_NULL("{\"type\":\"t\",\"challenge\":\"c\",\"origin\":\"o\",\"topOrigin\":null}", "!The client data's \"topOrigin\" is not a string"),
    CROSS_ORIGIN_NULL("{\"type\":\"t\",\"challenge\":\"c\",\"origin\":\"o\",\"crossOrigin\":null}", "!The client data's \"crossOrigin\" is not true or false"),
    NOT_AN_OBJECT("\"x\"", "!The client data is not a JSON object"),
    EMPTY("", "!The client data is not JSON at character 0: the JSON ends before a value"),
    ONLY_SPACE("  ", "!The client data is not JSON at character 2: the JSON ends before a value"),
    UNCLOSED_OBJECT("{\"type\":\"t\"", "!The client data is not JSON at character 11: expected , or }"),
    UNCLOSED_ARRAY("{\"x\":[1", "!The client data is not JSON at character 7: expected , or ]"),
    ARRAY_TRAILING_COMMA("{\"x\":[1,]}", "!The client data is not JSON at character 8: unexpected ']'"),
    OBJECT_TRAILING_COMMA("{\"x\":1,}", "!The client data is not JSON at character 7: expected a member name"),
    MISSING_COLON("{\"x\" 1}", "!The client data is not JSON at character 5: expected :"),
    UNQUOTED_NAME("{x:1}", "!The client data is not JSON at character 1: expected a member name"),
    SINGLE_QUOTES("{'x':1}", "!The client data is not JSON at character 1: expected a member name"),
    CONTROL_IN_STRING("{\"x\":\"a\u0001\"}", "!The client data is not JSON at character 7: a control character in a string"),
    BAD_ESCAPE("{\"x\":\"\\x\"}", "!The client data is not JSON at character 6: an unknown escape \\x"),
    SHORT_U_ESCAPE("{\"x\":\"\\u12\"}", "!The client data is not JSON at character 8: a \\u escape that is not four hex digits"),
    U_ESCAPE_AT_END("{\"x\":\"\\u12", "!The client data is not JSON at character 8: the JSON ends inside a \\u escape"),
    STRING_ENDS("{\"x\":\"abc", "!The client data is not JSON at character 9: the JSON ends inside a string"),
    ESCAPE_ENDS("{\"x\":\"\\", "!The client data is not JSON at character 7: the JSON ends inside a string"),
    LEADING_ZERO("{\"x\":01}", "!The client data is not JSON at character 6: expected , or }"),
    BARE_MINUS("{\"x\":-}", "!The client data is not JSON at character 6: a number without digits"),
    POINT_WITHOUT_DIGITS("{\"x\":1.}", "!The client data is not JSON at character 7: a number without digits after the point"),
    EXPONENT_WITHOUT_DIGITS("{\"x\":1e}", "!The client data is not JSON at character 7: a number without digits in its exponent"),
    SIGNED_EXPONENT_WITHOUT_DIGITS("{\"x\":1e+}", "!The client data is not JSON at character 8: a number without digits in its exponent"),
    HUGE_EXPONENT("{\"x\":1e999999999999,\"type\":\"t\",\"challenge\":\"c\",\"origin\":\"o\"}", "c"),
    TRUE_MISSPELLED("{\"x\":tru}", "!The client data is not JSON at character 5: unexpected 't'"),
    NULL_MISSPELLED("{\"x\":nul}", "!The client data is not JSON at character 5: unexpected 'n'"),
    NOT_A_VALUE("{\"x\":@}", "!The client data is not JSON at character 5: unexpected '@'"),
    NOT_A_VALUE_UNICODE("{\"x\":\u00e9}", "!The client data is not JSON at character 5: unexpected U+00E9"),
    BYTE_ORDER_MARK("\ufeff{}", "!The client data has no \"type\""),
    DUPLICATE_DEEP("{\"x\":{\"a\":1,\"a\":2}}", "!The client data is not JSON at character 12: the member \"a\" is there twice"),
    DEEP("[".repeat(32) + "]".repeat(32), "!The client data is not a JSON object"),
    TOO_DEEP("[".repeat(33) + "]".repeat(33), "!The client data is not JSON at character 32: JSON nested deeper than 32"),
    TOO_DEEP_OBJECTS("{\"a\":".repeat(33) + "1" + "}".repeat(33), "!The client data is not JSON at character 160: JSON nested deeper than 32");

    final String json;
    final String expected;

    ClientJson(String json, String expected) {
      this.json = json;
      this.expected = expected;
    }
  }

  @ParameterizedTest
  @EnumSource
  void clientData(ClientJson c) {
    byte[] bytes = c.json.getBytes(StandardCharsets.UTF_8);
    if (c.expected.startsWith("!")) {
      WebauthnException e = assertThrows(WebauthnException.class, () -> ClientData.read(bytes));
      assertEquals(WebauthnException.Reason.CLIENT_DATA, e.reason());
      assertEquals(c.expected.substring(1), e.getMessage());
    } else {
      assertEquals(c.expected, ClientData.read(bytes).challenge());
    }
  }

  @Test
  void clientDataSize() {
    String head = "{\"type\":\"t\",\"challenge\":\"c\",\"origin\":\"o\",\"x\":\"";
    String fits = head + "a".repeat(ClientData.MAX_BYTES - head.length() - 2) + "\"}";
    assertEquals(ClientData.MAX_BYTES, fits.length());
    assertEquals("c", ClientData.read(fits.getBytes(StandardCharsets.UTF_8)).challenge());
    String over = head + "a".repeat(ClientData.MAX_BYTES - head.length() - 1) + "\"}";
    assertEquals("The client data is 65537 bytes, more than 65536",
        assertThrows(WebauthnException.class, () -> ClientData.read(over.getBytes(StandardCharsets.UTF_8))).getMessage());
  }

  /// COSE keys the test authenticator wouldn't make, and what reading them
  /// says.
  enum Cose {
    OKP_ED448_WITH_ED25519_ALG("The credential public key's algorithm ED25519 does not go with its curve ED448"),
    OKP_ED25519_WITH_ED448_ALG("The credential public key's algorithm ED448 does not go with its curve ED25519"),
    OKP_WITH_ES256_ALG("The credential public key's algorithm ES256 does not go with its curve ED25519"),
    OKP_UNKNOWN_CURVE("The credential public key's OKP curve 4 is not one this library reads (6 Ed25519, 7 Ed448)"),
    OKP_SHORT("The credential public key must be 32 bytes for ED25519: it is 31"),
    OKP_LONG("The credential public key must be 57 bytes for ED448: it is 58"),
    OKP_NO_X("The credential public key has no x (-2)"),
    EC2_P384_WITH_ES512("The credential public key's algorithm ES512 does not go with its curve P384 (ES384 does)"),
    EC2_P521_WITH_ES256("The credential public key's algorithm ES256 does not go with its curve P521 (ES512 does)"),
    EC2_WITH_EDDSA("The credential public key's algorithm EDDSA does not go with its curve P256 (ES256 does)"),
    EC2_Y_ABOVE_PRIME("The credential public key's coordinates are not less than P256's prime"),
    EC2_NO_CURVE("The credential public key has no crv (-1)"),
    EC2_CURVE_TEXT("The credential public key's crv (-1) is not an integer: \"P-256\""),
    RSA_WITH_ES256("The credential public key's algorithm ES256 does not go with an RSA key"),
    RSA_1024("The credential public key's RSA modulus is 1024 bits, less than 2048"),
    RSA_2047("The credential public key's RSA modulus is 2047 bits, less than 2048"),
    RSA_EVEN_EXPONENT("The credential public key's RSA exponent is not an odd number from 3 to below the modulus"),
    RSA_EXPONENT_ONE("The credential public key's RSA exponent is not an odd number from 3 to below the modulus"),
    RSA_EXPONENT_THREE(""),
    RSA_EXPONENT_MODULUS("The credential public key's RSA exponent is not an odd number from 3 to below the modulus"),
    RSA_NO_N("The credential public key has no n (-1)"),
    RSA_PS256(""),
    NO_KEY_TYPE("The credential public key has no kty (1)"),
    NOT_A_MAP("The credential public key is not a COSE key (a CBOR map): CborBytes"),
    TRAILING_BYTES("The credential public key is not CBOR: Not well-formed CBOR at byte 77: 1 byte after the item");

    final String expected;

    Cose(String expected) {
      this.expected = expected;
    }
  }

  @ParameterizedTest
  @EnumSource
  void cose(Cose c) throws Exception {
    byte[] cose = switch (c) {
      case OKP_ED448_WITH_ED25519_ALG -> key(Kind.ED448, 3, WebauthnAlgorithm.ED25519.coseId());
      case OKP_ED25519_WITH_ED448_ALG -> key(Kind.ED25519, 3, WebauthnAlgorithm.ED448.coseId());
      case OKP_WITH_ES256_ALG -> key(Kind.ED25519, 3, -7);
      case OKP_UNKNOWN_CURVE -> key(Kind.ED25519, -1, 4);
      case OKP_SHORT -> key(Kind.ED25519, -2, new byte[31]);
      case OKP_LONG -> key(Kind.ED448, -2, new byte[58]);
      case OKP_NO_X -> without(Kind.ED25519, -2);
      case EC2_P384_WITH_ES512 -> key(Kind.ES384, 3, -36);
      case EC2_P521_WITH_ES256 -> key(Kind.ES512, 3, -7);
      case EC2_WITH_EDDSA -> key(Kind.ES256, 3, -8);
      case EC2_Y_ABOVE_PRIME -> key(Kind.ES256, -3, HexFormat.of().parseHex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"));
      case EC2_NO_CURVE -> without(Kind.ES256, -1);
      case EC2_CURVE_TEXT -> key(Kind.ES256, -1, "P-256");
      case RSA_WITH_ES256 -> key(Kind.RS256, 3, -7);
      case RSA_1024 -> rsa(1024, BigInteger.valueOf(65537));
      case RSA_2047 -> rsa(2047, BigInteger.valueOf(65537));
      case RSA_EVEN_EXPONENT -> rsa(2048, BigInteger.valueOf(65536));
      case RSA_EXPONENT_ONE -> rsa(2048, BigInteger.ONE);
      case RSA_EXPONENT_THREE -> rsa(2048, BigInteger.valueOf(3));
      case RSA_EXPONENT_MODULUS -> rsa(2048, null);
      case RSA_NO_N -> without(Kind.RS256, -1);
      case RSA_PS256 -> key(Kind.RS256, 3, -37);
      case NO_KEY_TYPE -> without(Kind.ES256, 1);
      case NOT_A_MAP -> TestCbor.encode(new byte[] {1});
      case TRAILING_BYTES -> CeremonyTest.concat(TestCbor.encode(TestAuthenticator.coseKey(Kind.ES256, TestAuthenticator.keys(Kind.ES256))), new byte[] {0});
    };
    if (c.expected.isEmpty()) {
      CoseKey.read(cose);
    } else {
      WebauthnException e = assertThrows(WebauthnException.class, () -> CoseKey.read(cose));
      assertEquals(WebauthnException.Reason.PUBLIC_KEY, e.reason());
      assertEquals(c.expected, e.getMessage());
    }
  }

  static byte[] key(Kind kind, int member, Object value) {
    Map<Object, Object> m = new LinkedHashMap<>(TestAuthenticator.coseKey(kind, TestAuthenticator.keys(kind)));
    m.put(member, value);
    return TestCbor.encode(m);
  }

  static byte[] without(Kind kind, int member) {
    Map<Object, Object> m = new LinkedHashMap<>(TestAuthenticator.coseKey(kind, TestAuthenticator.keys(kind)));
    m.remove(member);
    return TestCbor.encode(m);
  }

  /// An RSA key of some size; a null exponent is the modulus itself.
  static byte[] rsa(int bits, @org.jspecify.annotations.Nullable BigInteger e) throws Exception {
    BigInteger n;
    if (bits == 2048) {
      n = ((RSAPublicKey) TestAuthenticator.keys(Kind.RS256).getPublic()).getModulus();
    } else if (bits == 1024) {
      KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
      g.initialize(1024);
      n = ((RSAPublicKey) g.generateKeyPair().getPublic()).getModulus();
    } else {
      n = BigInteger.ONE.shiftLeft(bits - 1).add(BigInteger.ONE);
    }
    Map<Object, Object> m = new LinkedHashMap<>();
    m.put(1, 3);
    m.put(3, -257);
    m.put(-1, TestAuthenticator.unsigned(n));
    m.put(-2, TestAuthenticator.unsigned(e == null ? n : e));
    return TestCbor.encode(m);
  }

  @Test
  void authenticatorDataEdges() {
    Random random = new Random(9);
    Registration r = new Registration(Kind.ES256, random);
    byte[] whole = r.authenticatorData();
    // 37 + 16 (AAGUID) + 2 (length): the shortest that can hold the length.
    assertEquals("The authenticator data ends inside its attested credential data",
        assertThrows(WebauthnException.class, () -> AuthenticatorData.read(Arrays.copyOf(whole, 54))).getMessage());
    assertEquals("The authenticator data's credential ID of 16 bytes runs past its end",
        assertThrows(WebauthnException.class, () -> AuthenticatorData.read(Arrays.copyOf(whole, 55))).getMessage());
    assertEquals("The authenticator data's credential ID of 16 bytes runs past its end",
        assertThrows(WebauthnException.class, () -> AuthenticatorData.read(Arrays.copyOf(whole, 70))).getMessage());
    assertEquals("The authenticator data's credential public key is not CBOR: Not well-formed CBOR at byte 71: the input ends before an item",
        assertThrows(WebauthnException.class, () -> AuthenticatorData.read(Arrays.copyOf(whole, 71))).getMessage());
    assertEquals("The authenticator data has 2 bytes after its last part (the ED flag is not set)",
        assertThrows(WebauthnException.class, () -> AuthenticatorData.read(CeremonyTest.concat(whole, new byte[2]))).getMessage());
    r.flags |= TestAuthenticator.ED;
    r.extensions = TestCbor.encode(Map.of());
    r.trailing = new byte[1];
    assertEquals("The authenticator data has 1 byte after its last part",
        assertThrows(WebauthnException.class, () -> AuthenticatorData.read(r.authenticatorData())).getMessage());
    r.trailing = new byte[0];
    AuthenticatorData data = AuthenticatorData.read(r.authenticatorData());
    assertEquals("{}", String.valueOf(data.extensionsOrNull()));
    assertNull(AuthenticatorData.read(whole).extensionsOrNull());
    // The counter is unsigned.
    byte[] counted = whole.clone();
    counted[33] = (byte) 0xff;
    assertEquals(0xff000000L, AuthenticatorData.read(counted).signCount());
  }

  @Test
  void lostEligibility() {
    Random random = new Random(10);
    Registration r = new Registration(Kind.ES256, random);
    r.flags |= TestAuthenticator.BE;
    WebauthnCredential c = CeremonyTest.RP.register(r.build(), r.challenge, CeremonyTest.USER);
    TestAuthenticator.Assertion a = new TestAuthenticator.Assertion(r, random);
    CeremonyTest.outcome("BACKUP: The credential was registered backup eligible, and now says it is not",
        () -> CeremonyTest.RP.signIn(a.build(), a.challenge, c));
  }

  @Test
  void credentialEquality() {
    Registration r = new Registration(Kind.ES256, new Random(11));
    byte[] cose = r.publicKeyCose();
    byte[] user = CeremonyTest.USER;
    WebauthnCredential base = WebauthnCredential.builder(new byte[] {1}, cose, user).build();
    assertEquals(base, WebauthnCredential.builder(new byte[] {1}, cose, user).build());
    Registration other = new Registration(Kind.ES256, new Random(12));
    other.cose = TestAuthenticator.coseKey(Kind.ES384, TestAuthenticator.keys(Kind.ES384));
    for (WebauthnCredential different : new WebauthnCredential[] {
        WebauthnCredential.builder(new byte[] {2}, cose, user).build(),
        WebauthnCredential.builder(new byte[] {1}, other.publicKeyCose(), user).build(),
        WebauthnCredential.builder(new byte[] {1}, cose, new byte[] {9}).build(),
        WebauthnCredential.builder(new byte[] {1}, cose, user).signCount(1).build(),
        WebauthnCredential.builder(new byte[] {1}, cose, user).backupEligible(true).build(),
        WebauthnCredential.builder(new byte[] {1}, cose, user).backupEligible(true).backedUp(true).build(),
        WebauthnCredential.builder(new byte[] {1}, cose, user).aaguid(new UUID(0, 1)).build(),
        WebauthnCredential.builder(new byte[] {1}, cose, user).attestationFormat("packed").build()}) {
      assertEquals(false, base.equals(different), different.toString());
    }
    assertEquals(false, base.equals((Object) "credential"));
    assertEquals(false, base.hashCode() == WebauthnCredential.builder(new byte[] {2}, cose, user).build().hashCode());
    assertEquals("WebauthnCredential[ES256, 1-byte ID, signCount 0]", base.toString());
    assertEquals("WebauthnCredential[ES256, 1-byte ID, signCount 0, backup eligible]",
        WebauthnCredential.builder(new byte[] {1}, cose, user).backupEligible(true).build().toString());

    byte[] handle = {4, 5};
    WebauthnAssertion a = WebauthnAssertion.builder().credentialId(handle).clientDataJson(handle).authenticatorData(handle).signature(handle).userHandle(handle).build();
    handle[0] = 9;
    byte[] out = a.userHandleOrNull();
    assertArrayEquals(new byte[] {4, 5}, out);
    if (out != null) {
      out[1] = 9;
    }
    assertArrayEquals(new byte[] {4, 5}, a.userHandleOrNull());
  }
}
