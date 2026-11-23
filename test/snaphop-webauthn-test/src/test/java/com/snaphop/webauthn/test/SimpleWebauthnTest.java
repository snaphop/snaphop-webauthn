package com.snaphop.webauthn.test;

import static com.snaphop.webauthn.test.TestAuthenticator.BE;
import static com.snaphop.webauthn.test.TestAuthenticator.BS;
import static com.snaphop.webauthn.test.TestAuthenticator.UP;
import static com.snaphop.webauthn.test.TestAuthenticator.b64;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.snaphop.webauthn.WebauthnAssertion;
import com.snaphop.webauthn.WebauthnCredential;
import com.snaphop.webauthn.WebauthnException;
import com.snaphop.webauthn.WebauthnRelyingParty;
import com.snaphop.webauthn.WebauthnRelyingParty.RegistrationMediation;
import com.snaphop.webauthn.WebauthnSignIn;
import com.snaphop.webauthn.test.TestAuthenticator.Assertion;
import com.snaphop.webauthn.test.TestAuthenticator.Kind;
import com.snaphop.webauthn.test.TestAuthenticator.Registration;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/// Send the same browser-shaped fixtures to our Java verifier and to
/// SimpleWebAuthn running on Node. Compare stored credentials as well as
/// authentication verdicts.
class SimpleWebauthnTest {

  private static final Path ORACLE = Path.of("simplewebauthn");
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final byte[] USER = "reference-user".getBytes(StandardCharsets.UTF_8);

  @BeforeAll
  static void checkOracleInstalled() {
    boolean installed = Files.isRegularFile(ORACLE.resolve("node_modules/@simplewebauthn/server/package.json"));
    String message = "Install the JavaScript oracle with Node 22+ and npm ci --prefix test/snaphop-webauthn-test/simplewebauthn";
    if (Boolean.getBoolean("simplewebauthn.required")) {
      assertTrue(installed, message);
    } else {
      assumeTrue(installed, message);
    }
  }

  @ParameterizedTest
  @EnumSource(names = {"ES256", "ES384", "ES512", "ED25519", "RS256", "PS256"})
  void verifyWithSimpleWebauthn(Kind kind) throws Exception {
    Random random = new Random(kind.name().hashCode());
    Registration registration = new Registration(kind, random);
    boolean conditional = kind == Kind.ES256;
    if (conditional) {
      registration.flags &= ~UP;
    }
    registration.flags |= BE | BS;
    registration.signCount = 3;

    WebauthnRelyingParty rp = WebauthnRelyingParty.builder()
        .id(TestAuthenticator.RP_ID).origin(TestAuthenticator.ORIGIN)
        .algorithms(kind.algorithm).build();
    RegistrationMediation mediation = conditional ? RegistrationMediation.CONDITIONAL : RegistrationMediation.STANDARD;
    var creation = registration.build();
    WebauthnCredential stored = rp.register(creation, registration.challenge, USER, mediation);

    Assertion valid = new Assertion(registration, random);
    valid.flags |= BE;
    valid.signCount = 4;
    Assertion unverified = new Assertion(registration, random);
    unverified.flags = BE | UP;
    unverified.signCount = 4;
    Assertion oldCounter = new Assertion(registration, random);
    oldCounter.flags |= BE;
    oldCounter.signCount = 3;
    List<Check> checks = List.of(
        new Check("valid", valid.build(), b64(valid.challenge), true),
        new Check("wrong challenge", valid.build(), b64(registration.challenge), false),
        new Check("user verification missing", unverified.build(), b64(unverified.challenge), false),
        new Check("counter did not increase", oldCounter.build(), b64(oldCounter.challenge), false));

    Map<String, Object> fixture = Map.of(
        "expectedOrigin", TestAuthenticator.ORIGIN,
        "expectedRPID", TestAuthenticator.RP_ID,
        "registration", Map.of(
            "response", browserResponse(registration.credentialId, Map.of(
                "clientDataJSON", b64(creation.clientDataJson()), "attestationObject", b64(creation.attestationObject()))),
            "expectedChallenge", b64(registration.challenge), "algorithm", kind.algorithm.coseId(),
            "conditional", conditional),
        "assertions", checks.stream().map(Check::fixture).toList());
    JsonNode result = runOracle(fixture);
    JsonNode registered = result.required("registration");
    checkCredential(registered, stored);
    assertEquals(b64(stored.publicKeyCose()), registered.required("publicKey").asText());
    assertEquals(stored.attestationFormat(), registered.required("format").asText());

    JsonNode assertions = result.required("assertions");
    assertEquals(checks.size(), assertions.size());
    for (int i = 0; i < checks.size(); i++) {
      Check check = checks.get(i);
      JsonNode verdict = assertions.get(i);
      assertEquals(check.accepted(), verdict.required("verified").asBoolean(), check.name() + ": " + verdict);
      try {
        WebauthnSignIn signedIn = rp.signIn(check.response(), Base64.getUrlDecoder().decode(check.challenge()), stored);
        assertTrue(check.accepted(), check.name() + " should have been refused");
        assertEquals(signedIn.userVerified(), verdict.required("userVerified").asBoolean());
        checkCredential(verdict, signedIn.credential());
      } catch (WebauthnException e) {
        assertFalse(check.accepted(), check.name() + ": " + e);
      }
    }
  }

  private static void checkCredential(JsonNode reference, WebauthnCredential ours) {
    assertEquals(b64(ours.credentialId()), reference.required("id").asText());
    assertEquals(ours.signCount(), reference.required("counter").asLong());
    assertEquals(ours.backupEligible(), reference.required("backupEligible").asBoolean());
    assertEquals(ours.backedUp(), reference.required("backedUp").asBoolean());
  }

  private static Map<String, Object> browserResponse(byte[] id, Map<String, String> response) {
    return Map.of("id", b64(id), "rawId", b64(id), "type", "public-key", "clientExtensionResults", Map.of(), "response", response);
  }

  private static JsonNode runOracle(Map<String, Object> fixture) throws IOException, InterruptedException {
    Process node = new ProcessBuilder("node", "oracle.mjs").directory(ORACLE.toFile())
        .redirectError(ProcessBuilder.Redirect.INHERIT).start();
    try {
      try (var input = node.getOutputStream()) {
        JSON.writeValue(input, fixture);
      }
      assertTrue(node.waitFor(30, TimeUnit.SECONDS), "The SimpleWebAuthn oracle timed out");
      assertEquals(0, node.exitValue(), "The SimpleWebAuthn oracle could not read the fixture");
      try (var output = node.getInputStream()) {
        return JSON.readTree(output);
      }
    } finally {
      node.destroyForcibly();
    }
  }

  private record Check(String name, WebauthnAssertion response, String challenge, boolean accepted) {
    Map<String, Object> fixture() {
      return Map.of(
          "response", browserResponse(response.credentialId(), Map.of(
              "clientDataJSON", b64(response.clientDataJson()), "authenticatorData", b64(response.authenticatorData()),
              "signature", b64(response.signature()))),
          "expectedChallenge", challenge);
    }
  }
}
