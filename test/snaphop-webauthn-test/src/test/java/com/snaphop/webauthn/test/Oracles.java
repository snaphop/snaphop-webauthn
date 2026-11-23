package com.snaphop.webauthn.test;

import com.snaphop.webauthn.WebauthnAlgorithm;
import com.snaphop.webauthn.WebauthnAssertion;
import com.snaphop.webauthn.WebauthnCredential;
import com.snaphop.webauthn.WebauthnException;
import com.snaphop.webauthn.WebauthnRegistration;
import com.snaphop.webauthn.WebauthnRelyingParty;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/// The same registration or sign-in, checked by this library, webauthn4j
/// and Yubico's java-webauthn-server, each set up the same way: RP ID
/// `example.org`, origin `https://example.org`, user verification
/// required, every algorithm all three know, attestation not checked.
final class Oracles {

  private Oracles() {}

  static final String RP_ID = TestAuthenticator.RP_ID;
  static final String ORIGIN = TestAuthenticator.ORIGIN;

  /// The algorithms all three check. Ed448 and ES512 are left out: Yubico
  /// checks neither (and webauthn4j's EdDSA is Ed25519).
  static final List<WebauthnAlgorithm> COMMON = List.of(
      WebauthnAlgorithm.ES256, WebauthnAlgorithm.ES384, WebauthnAlgorithm.EDDSA, WebauthnAlgorithm.RS256);

  static final WebauthnRelyingParty OURS = WebauthnRelyingParty.builder()
      .id(RP_ID).origin(ORIGIN)
      .algorithms(COMMON.toArray(WebauthnAlgorithm[]::new))
      .attestation(WebauthnRelyingParty.Attestation.ANY_UNVERIFIED)
      .build();

  static final WebAuthnManager WEBAUTHN4J = WebAuthnManager.createNonStrictWebAuthnManager();

  /// What one library said: accepted, or refused and why.
  record Verdict(boolean accepted, String detail) {
    static final Verdict OK = new Verdict(true, "OK");

    static Verdict refused(Throwable e) {
      return new Verdict(false, e.getClass().getSimpleName() + ": " + e.getMessage());
    }

    @Override
    public String toString() {
      return detail;
    }
  }

  /// The three verdicts on one ceremony.
  record Verdicts(Verdict ours, Verdict webauthn4j, Verdict yubico) {
    boolean agree() {
      return ours.accepted() == webauthn4j.accepted() && ours.accepted() == yubico.accepted();
    }

    /// Accepted by us and refused by either other: never allowed. What this
    /// library accepts, both oracles accept.
    boolean oursLooser() {
      return ours.accepted() && !(webauthn4j.accepted() && yubico.accepted());
    }

    String summary() {
      return "ours " + ours + "\n  webauthn4j " + webauthn4j + "\n  yubico " + yubico;
    }
  }

  // ---------------------------------------------------------------- registration

  static Verdicts register(byte[] clientDataJson, byte[] attestationObject, byte[] challenge, byte[] userHandle, byte[] credentialId) {
    return new Verdicts(
        verdict(() -> OURS.register(WebauthnRegistration.of(clientDataJson, attestationObject), challenge, userHandle)),
        verdict(() -> webauthn4jRegister(clientDataJson, attestationObject, challenge)),
        verdict(() -> yubicoRegister(clientDataJson, attestationObject, challenge, userHandle, credentialId)));
  }

  static RegistrationData webauthn4jRegister(byte[] clientDataJson, byte[] attestationObject, byte[] challenge) {
    RegistrationRequest request = new RegistrationRequest(attestationObject, clientDataJson);
    List<PublicKeyCredentialParameters> params = COMMON.stream()
        .map(a -> new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.create(a.coseId())))
        .toList();
    RegistrationParameters parameters = new RegistrationParameters(server(challenge), params, true, true);
    return WEBAUTHN4J.verify(request, parameters);
  }

  static ServerProperty server(byte[] challenge) {
    return ServerProperty.builder().origin(new Origin(ORIGIN)).rpId(RP_ID).challenge(new DefaultChallenge(challenge)).build();
  }

  static RegistrationResult yubicoRegister(byte[] clientDataJson, byte[] attestationObject, byte[] challenge, byte[] userHandle, byte[] credentialId) throws Exception {
    String json = "{\"id\":\"" + b64(credentialId) + "\",\"rawId\":\"" + b64(credentialId) + "\",\"type\":\"public-key\","
        + "\"response\":{\"clientDataJSON\":\"" + b64(clientDataJson) + "\",\"attestationObject\":\"" + b64(attestationObject) + "\"},"
        + "\"clientExtensionResults\":{}}";
    PublicKeyCredentialCreationOptions options = PublicKeyCredentialCreationOptions.builder()
        .rp(RelyingPartyIdentity.builder().id(RP_ID).name("Example").build())
        .user(UserIdentity.builder().name("user").displayName("User").id(new ByteArray(userHandle)).build())
        .challenge(new ByteArray(challenge))
        .pubKeyCredParams(COMMON.stream().map(a -> com.yubico.webauthn.data.PublicKeyCredentialParameters.builder()
            .alg(com.yubico.webauthn.data.COSEAlgorithmIdentifier.fromId(a.coseId()).orElseThrow()).build()).toList())
        .authenticatorSelection(AuthenticatorSelectionCriteria.builder().userVerification(UserVerificationRequirement.REQUIRED).build())
        .build();
    return yubico(null).finishRegistration(FinishRegistrationOptions.builder()
        .request(options)
        .response(PublicKeyCredential.parseRegistrationResponseJson(json))
        .build());
  }

  // ---------------------------------------------------------------- sign-in

  /// A credential as each library stored it after a registration they all
  /// accepted.
  record Stored(WebauthnCredential ours, CredentialRecordImpl webauthn4j, RegisteredCredential yubico) {}

  @SuppressWarnings("deprecation") // Yubico's backup flags are marked experimental.
  static Stored store(byte[] clientDataJson, byte[] attestationObject, byte[] challenge, byte[] userHandle, byte[] credentialId, long signCount) {
    WebauthnCredential ours = OURS.register(WebauthnRegistration.of(clientDataJson, attestationObject), challenge, userHandle);
    RegistrationData data = webauthn4jRegister(clientDataJson, attestationObject, challenge);
    CredentialRecordImpl record = new CredentialRecordImpl(
        java.util.Objects.requireNonNull(data.getAttestationObject()),
        java.util.Objects.requireNonNull(data.getCollectedClientData()),
        data.getClientExtensions(), data.getTransports());
    record.setCounter(signCount);
    RegistrationResult result;
    try {
      result = yubicoRegister(clientDataJson, attestationObject, challenge, userHandle, credentialId);
    } catch (Exception e) {
      throw new AssertionError("Yubico refused a registration to store", e);
    }
    RegisteredCredential yubico = RegisteredCredential.builder()
        .credentialId(result.getKeyId().getId())
        .userHandle(new ByteArray(userHandle))
        .publicKeyCose(result.getPublicKeyCose())
        .signatureCount(signCount)
        .backupEligible(result.isBackupEligible())
        .backupState(result.isBackedUp())
        .build();
    WebauthnCredential oursCounted = WebauthnCredential.builder(ours.credentialId(), ours.publicKeyCose(), ours.userHandle())
        .signCount(signCount).backupEligible(ours.backupEligible()).backedUp(ours.backedUp()).build();
    return new Stored(oursCounted, record, yubico);
  }

  static Verdicts signIn(Stored stored, WebauthnAssertion a, byte[] challenge) {
    return new Verdicts(
        verdict(() -> OURS.signIn(a, challenge, stored.ours())),
        verdict(() -> {
          AuthenticationRequest request = new AuthenticationRequest(a.credentialId(), a.userHandleOrNull(), a.authenticatorData(), a.clientDataJson(), a.signature());
          AuthenticationParameters parameters = new AuthenticationParameters(server(challenge), stored.webauthn4j(), List.of(stored.ours().credentialId()), true, true);
          return WEBAUTHN4J.verify(request, parameters);
        }),
        verdict(() -> {
          byte[] handle = a.userHandleOrNull();
          String json = "{\"id\":\"" + b64(a.credentialId()) + "\",\"rawId\":\"" + b64(a.credentialId()) + "\",\"type\":\"public-key\","
              + "\"response\":{\"clientDataJSON\":\"" + b64(a.clientDataJson()) + "\",\"authenticatorData\":\"" + b64(a.authenticatorData())
              + "\",\"signature\":\"" + b64(a.signature()) + "\"" + (handle == null ? "" : ",\"userHandle\":\"" + b64(handle) + "\"") + "},"
              + "\"clientExtensionResults\":{}}";
          AssertionRequest request = AssertionRequest.builder()
              .publicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions.builder()
                  .challenge(new ByteArray(challenge))
                  .rpId(RP_ID)
                  .userVerification(UserVerificationRequirement.REQUIRED)
                  .build())
              .userHandle(stored.yubico().getUserHandle())
              .build();
          return yubico(stored.yubico()).finishAssertion(FinishAssertionOptions.builder()
              .request(request)
              .response(PublicKeyCredential.parseAssertionResponseJson(json))
              .build());
        }));
  }

  // ---------------------------------------------------------------- plumbing

  static RelyingParty yubico(@Nullable RegisteredCredential credential) {
    return RelyingParty.builder()
        .identity(RelyingPartyIdentity.builder().id(RP_ID).name("Example").build())
        .credentialRepository(new Repository(credential))
        .origins(Set.of(ORIGIN))
        .allowUntrustedAttestation(true)
        .build();
  }

  /// Holds at most one credential: the one signing in.
  static final class Repository implements CredentialRepository {
    private final @Nullable RegisteredCredential credential;

    Repository(@Nullable RegisteredCredential credential) {
      this.credential = credential;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
      RegisteredCredential c = credential;
      return c == null ? Set.of() : Set.of(PublicKeyCredentialDescriptor.builder().id(c.getCredentialId()).build());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
      RegisteredCredential c = credential;
      return c == null ? Optional.empty() : Optional.of(c.getUserHandle());
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
      RegisteredCredential c = credential;
      return c != null && c.getUserHandle().equals(userHandle) ? Optional.of("user") : Optional.empty();
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
      RegisteredCredential c = credential;
      return c != null && c.getCredentialId().equals(credentialId) && c.getUserHandle().equals(userHandle) ? Optional.of(c) : Optional.empty();
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
      RegisteredCredential c = credential;
      return c != null && c.getCredentialId().equals(credentialId) ? Set.of(c) : Set.of();
    }
  }

  interface Ceremony {
    Object run() throws Exception;
  }

  static Verdict verdict(Ceremony c) {
    try {
      c.run();
      return Verdict.OK;
    } catch (WebauthnException e) {
      return new Verdict(false, e.reason() + ": " + e.getMessage());
    } catch (Exception | AssertionError e) {
      return Verdict.refused(e);
    }
  }

  static String b64(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  static byte[] concat(byte[] a, byte[] b) {
    byte[] out = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }
}
