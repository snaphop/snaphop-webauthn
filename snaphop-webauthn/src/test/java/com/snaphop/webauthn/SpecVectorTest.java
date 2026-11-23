package com.snaphop.webauthn;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/// The WebAuthn Level 3 test vectors (section 16): each registration is
/// accepted and its sign-in verifies with the key it registered.
class SpecVectorTest {

  static final Path VECTORS = Path.of("../test/corpus/webauthn-spec/test-vectors.txt");

  static final WebauthnRelyingParty RP = WebauthnRelyingParty.builder()
      .id("example.org")
      .origin("https://example.org")
      .crossOrigin(WebauthnRelyingParty.CrossOrigin.ALLOW)
      .topOrigin("https://example.com")
      // The vectors set UV at random.
      .userVerification(WebauthnRelyingParty.UserVerification.PREFERRED)
      .algorithms(WebauthnAlgorithm.values())
      // Packed, TPM, Android Key, Apple and FIDO U2F statements are accepted
      // without being checked.
      .attestation(WebauthnRelyingParty.Attestation.ANY_UNVERIFIED)
      .build();

  /// What each section is: its algorithm and attestation format.
  enum Vector {
    NONE_ES256("16.2", WebauthnAlgorithm.ES256, "none"),
    PACKED_SELF_ES256("16.3", WebauthnAlgorithm.ES256, "packed"),
    CROSS_ORIGIN("16.4", WebauthnAlgorithm.ES256, "none"),
    TOP_ORIGIN("16.5", WebauthnAlgorithm.ES256, "none"),
    LONG_CREDENTIAL_ID("16.6", WebauthnAlgorithm.ES256, "none"),
    PACKED_ES256("16.7", WebauthnAlgorithm.ES256, "packed"),
    PACKED_ES384("16.8", WebauthnAlgorithm.ES384, "packed"),
    PACKED_ES512("16.9", WebauthnAlgorithm.ES512, "packed"),
    PACKED_RS256("16.10", WebauthnAlgorithm.RS256, "packed"),
    PACKED_ED25519("16.11", WebauthnAlgorithm.EDDSA, "packed"),
    PACKED_ED448("16.12", WebauthnAlgorithm.ED448, "packed"),
    TPM_ES256("16.13", WebauthnAlgorithm.ES256, "tpm"),
    ANDROID_KEY_ES256("16.14", WebauthnAlgorithm.ES256, "android-key"),
    APPLE_ES256("16.15", WebauthnAlgorithm.ES256, "apple"),
    FIDO_U2F_ES256("16.16", WebauthnAlgorithm.ES256, "fido-u2f");

    final String section;
    final WebauthnAlgorithm algorithm;
    final String format;

    Vector(String section, WebauthnAlgorithm algorithm, String format) {
      this.section = section;
      this.algorithm = algorithm;
      this.format = format;
    }
  }

  static Map<String, Map<String, byte[]>> sections() throws IOException {
    Map<String, Map<String, byte[]>> sections = new LinkedHashMap<>();
    Map<String, byte[]> current = null;
    for (String line : Files.readAllLines(VECTORS, StandardCharsets.UTF_8)) {
      if (line.startsWith("[")) {
        current = new LinkedHashMap<>();
        sections.put(line.substring(1, line.indexOf(' ')), current);
      } else if (current != null && line.contains(" = ")) {
        String[] kv = line.split(" = ", 2);
        current.put(kv[0], HexFormat.of().parseHex(kv[1]));
      }
    }
    return sections;
  }

  static Stream<Arguments> vectors() throws IOException {
    Map<String, Map<String, byte[]>> sections = sections();
    return Stream.of(Vector.values()).map(v -> Arguments.of(v, Objects.requireNonNull(sections.get(v.section), v.section)));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("vectors")
  void vector(Vector v, Map<String, byte[]> values) {
    byte[] user = "user".getBytes(StandardCharsets.UTF_8);
    WebauthnCredential c = RP.register(
        WebauthnRegistration.of(get(values, "registration.clientDataJSON"), get(values, "registration.attestationObject")),
        get(values, "registration.challenge"), user);
    assertEquals(v.algorithm, c.algorithm());
    assertEquals(v.format, c.attestationFormat());
    assertArrayEquals(get(values, "registration.credential_id"), c.credentialId());
    assertEquals(uuid(get(values, "registration.aaguid")), c.aaguid());

    byte[] authenticatorData = get(values, "authentication.authenticatorData");
    WebauthnAssertion assertion = WebauthnAssertion.builder()
        .credentialId(c.credentialId())
        .clientDataJson(get(values, "authentication.clientDataJSON"))
        .authenticatorData(authenticatorData)
        .signature(get(values, "authentication.signature"))
        .build();
    WebauthnSignIn signIn = RP.signIn(assertion, get(values, "authentication.challenge"), c);
    assertEquals(WebauthnSignIn.SignCount.ZERO, signIn.signCount());
    assertEquals((authenticatorData[32] & 0x04) != 0, signIn.userVerified());
    assertEquals((authenticatorData[32] & 0x10) != 0, signIn.credential().backedUp());

    // The sign-in fails with a challenge it wasn't given, and with any bit
    // of its signature flipped.
    WebauthnException challenge = assertThrows(WebauthnException.class, () -> RP.signIn(assertion, get(values, "registration.challenge"), c));
    assertEquals(WebauthnException.Reason.CHALLENGE, challenge.reason());
    byte[] signature = get(values, "authentication.signature");
    for (int bit = 0; bit < signature.length * 8; bit += 7) {
      byte[] flipped = signature.clone();
      flipped[bit / 8] ^= (byte) (1 << (bit % 8));
      WebauthnAssertion bad = WebauthnAssertion.builder()
          .credentialId(c.credentialId())
          .clientDataJson(get(values, "authentication.clientDataJSON"))
          .authenticatorData(authenticatorData)
          .signature(flipped)
          .build();
      WebauthnException e = assertThrows(WebauthnException.class, () -> RP.signIn(bad, get(values, "authentication.challenge"), c));
      assertEquals(WebauthnException.Reason.SIGNATURE, e.reason());
    }

    // Only "none" is accepted by a relying party left at its default.
    WebauthnRelyingParty strict = WebauthnRelyingParty.builder().id("example.org").origin("https://example.org")
        .crossOrigin(WebauthnRelyingParty.CrossOrigin.ALLOW).topOrigin("https://example.com")
        .userVerification(WebauthnRelyingParty.UserVerification.PREFERRED).algorithms(WebauthnAlgorithm.values()).build();
    WebauthnRegistration registration = WebauthnRegistration.of(get(values, "registration.clientDataJSON"), get(values, "registration.attestationObject"));
    if (v.format.equals("none")) {
      strict.register(registration, get(values, "registration.challenge"), user);
    } else {
      WebauthnException e = assertThrows(WebauthnException.class, () -> strict.register(registration, get(values, "registration.challenge"), user));
      assertEquals("The attestation format \"" + v.format + "\" is not \"none\", the only one this relying party accepts", e.getMessage());
    }
  }

  static byte[] get(Map<String, byte[]> values, String key) {
    return Objects.requireNonNull(values.get(key), key).clone();
  }

  static UUID uuid(byte[] b) {
    java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(b);
    return new UUID(buffer.getLong(), buffer.getLong());
  }
}
