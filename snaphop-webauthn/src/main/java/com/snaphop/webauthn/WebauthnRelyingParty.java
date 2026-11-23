package com.snaphop.webauthn;

import com.snaphop.cbor.CborBytes;
import com.snaphop.cbor.CborMap;
import com.snaphop.cbor.CborParseException;
import com.snaphop.cbor.CborReader;
import com.snaphop.cbor.CborText;
import com.snaphop.cbor.CborValue;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.jspecify.annotations.Nullable;

/// A website that registers passkeys and signs people in with them: checks
/// what browsers return, as WebAuthn Level 3 sections 7.1 and 7.2 say.
///
/// ```java
/// WebauthnRelyingParty rp = WebauthnRelyingParty.builder()
///     .id("example.org")
///     .origin("https://example.org")
///     .build();
///
/// // Registering: the challenge and user handle are the ones in the options
/// // given to navigator.credentials.create().
/// WebauthnCredential credential = rp.register(WebauthnRegistration.of(clientDataJson, attestationObject), challenge, userHandle);
///
/// // Signing in: look the stored credential up by the response's credential ID.
/// WebauthnSignIn signIn = rp.signIn(assertion, challenge, stored);
/// store(signIn.credential());
/// ```
///
/// Anything refused is a [WebauthnException] with its
/// [WebauthnException.Reason]. Challenges are the caller's: 32 or more
/// random bytes, used once, and forgotten after a few minutes.
public sealed interface WebauthnRelyingParty permits DefaultWebauthnRelyingParty {

  /// Whether the user must be verified (biometrics or a PIN), as in the
  /// options' `userVerification`.
  enum UserVerification {
    /// The UV flag must be set. The default: a passkey stands in for a
    /// password and a second factor only when the user was verified.
    REQUIRED,
    /// Asked for but not required: the UV flag is reported, not checked.
    PREFERRED,
    /// Not asked for: the UV flag is reported, not checked.
    DISCOURAGED
  }

  /// Whether a response may come from inside a frame of another origin
  /// (the client data's `crossOrigin`).
  enum CrossOrigin {
    /// `crossOrigin` must be absent or false, and `topOrigin` absent. The
    /// default.
    REFUSE,
    /// `crossOrigin` may be true. A `topOrigin`, when there is one, must
    /// be one of [Builder#topOrigin(String)]'s.
    ALLOW
  }

  /// Which attestation statements a registration may carry.
  ///
  /// Neither mode checks an attestation statement's signature or
  /// certificates: this library does not verify attestation, which tells
  /// who made an authenticator. Passkeys usually come with none.
  enum Attestation {
    /// Only the `none` format, with an empty statement. The default, and
    /// what browsers send when the options ask for `"attestation": "none"`.
    NONE,
    /// Any format, recorded in [WebauthnCredential#attestationFormat()]
    /// and not checked. A `none` statement must still be empty.
    ANY_UNVERIFIED
  }

  /// What to do when the signature counter did not increase.
  enum SignCountCheck {
    /// Refuse the sign-in ([WebauthnException.Reason#SIGN_COUNT]). The
    /// default.
    REFUSE,
    /// Accept it, and say so in [WebauthnSignIn#signCount()].
    REPORT
  }

  /// A new builder.
  ///
  /// @return the builder
  static Builder builder() {
    return new Builder();
  }

  /// The RP ID: the domain credentials are made for.
  ///
  /// @return the RP ID, such as `example.org`
  String id();

  /// Checks a registration and returns the credential to store.
  ///
  /// @param response what `navigator.credentials.create()` returned
  /// @param challenge the options' `challenge`
  /// @param userHandle the options' `user.id`, 1 to 64 bytes
  /// @return the credential
  /// @throws WebauthnException if the registration is refused
  /// @throws IllegalArgumentException if the user handle is empty or longer
  ///     than 64 bytes
  WebauthnCredential register(WebauthnRegistration response, byte[] challenge, byte[] userHandle);

  /// Checks a sign-in against the stored credential its credential ID
  /// names.
  ///
  /// @param response what `navigator.credentials.get()` returned
  /// @param challenge the options' `challenge`
  /// @param credential the stored credential
  /// @return what was accepted, with the credential to store
  /// @throws WebauthnException if the sign-in is refused
  WebauthnSignIn signIn(WebauthnAssertion response, byte[] challenge, WebauthnCredential credential);

  /// Configures a [WebauthnRelyingParty].
  final class Builder {

    private @Nullable String id;
    private final Set<String> origins = new LinkedHashSet<>();
    private final Set<String> topOrigins = new LinkedHashSet<>();
    private CrossOrigin crossOrigin = CrossOrigin.REFUSE;
    private UserVerification userVerification = UserVerification.REQUIRED;
    private Set<WebauthnAlgorithm> algorithms = EnumSet.of(WebauthnAlgorithm.ES256, WebauthnAlgorithm.EDDSA, WebauthnAlgorithm.RS256);
    private Attestation attestation = Attestation.NONE;
    private SignCountCheck signCountCheck = SignCountCheck.REFUSE;

    private Builder() {}

    /// The RP ID: a domain, such as `example.org`. Required.
    ///
    /// @param id the RP ID
    /// @return this builder
    public Builder id(String id) {
      this.id = Objects.requireNonNull(id);
      return this;
    }

    /// An origin the relying party is served from, exactly as browsers
    /// write it: `https://example.org`, no path, no slash at the end. At
    /// least one is required; each call adds one.
    ///
    /// @param origin the origin
    /// @return this builder
    public Builder origin(String origin) {
      origins.add(Objects.requireNonNull(origin));
      return this;
    }

    /// Whether responses may come from a frame of another origin,
    /// [CrossOrigin#REFUSE] until set.
    ///
    /// @param crossOrigin the mode
    /// @return this builder
    public Builder crossOrigin(CrossOrigin crossOrigin) {
      this.crossOrigin = Objects.requireNonNull(crossOrigin);
      return this;
    }

    /// An origin of a page the relying party may be framed in, as the
    /// client data's `topOrigin`. Each call adds one. Used only with
    /// [CrossOrigin#ALLOW].
    ///
    /// @param topOrigin the origin
    /// @return this builder
    public Builder topOrigin(String topOrigin) {
      topOrigins.add(Objects.requireNonNull(topOrigin));
      return this;
    }

    /// Whether the user must be verified, [UserVerification#REQUIRED] until
    /// set. Use the same as the options' `userVerification`.
    ///
    /// @param userVerification the mode
    /// @return this builder
    public Builder userVerification(UserVerification userVerification) {
      this.userVerification = Objects.requireNonNull(userVerification);
      return this;
    }

    /// The algorithms a credential may use: the options'
    /// `pubKeyCredParams`. [WebauthnAlgorithm#ES256], [WebauthnAlgorithm#EDDSA]
    /// and [WebauthnAlgorithm#RS256] until set.
    ///
    /// @param algorithms one or more algorithms
    /// @return this builder
    /// @throws IllegalArgumentException if there are none
    public Builder algorithms(WebauthnAlgorithm... algorithms) {
      if (algorithms.length == 0) {
        throw new IllegalArgumentException("At least one algorithm is needed");
      }
      this.algorithms = EnumSet.copyOf(List.of(algorithms));
      return this;
    }

    /// Which attestation statements to accept, [Attestation#NONE] until set.
    ///
    /// @param attestation the mode
    /// @return this builder
    public Builder attestation(Attestation attestation) {
      this.attestation = Objects.requireNonNull(attestation);
      return this;
    }

    /// What to do when a signature counter does not increase,
    /// [SignCountCheck#REFUSE] until set.
    ///
    /// @param signCountCheck the mode
    /// @return this builder
    public Builder signCountCheck(SignCountCheck signCountCheck) {
      this.signCountCheck = Objects.requireNonNull(signCountCheck);
      return this;
    }

    /// The relying party.
    ///
    /// @return the relying party
    /// @throws IllegalStateException without an RP ID or an origin
    public WebauthnRelyingParty build() {
      String rpId = id;
      if (rpId == null || rpId.isEmpty()) {
        throw new IllegalStateException("A relying party needs an RP ID: id(\"example.org\")");
      }
      if (origins.isEmpty()) {
        throw new IllegalStateException("A relying party needs at least one origin: origin(\"https://" + rpId + "\")");
      }
      return new DefaultWebauthnRelyingParty(rpId, Set.copyOf(origins), Set.copyOf(topOrigins), crossOrigin, userVerification,
          Set.copyOf(algorithms), attestation, signCountCheck, DefaultWebauthnRelyingParty.sha256(rpId.getBytes(StandardCharsets.UTF_8)));
    }
  }
}

final class DefaultWebauthnRelyingParty implements WebauthnRelyingParty {

  private final String id;
  private final Set<String> origins;
  private final Set<String> topOrigins;
  private final WebauthnRelyingParty.CrossOrigin crossOrigin;
  private final WebauthnRelyingParty.UserVerification userVerification;
  private final Set<WebauthnAlgorithm> algorithms;
  private final WebauthnRelyingParty.Attestation attestation;
  private final WebauthnRelyingParty.SignCountCheck signCountCheck;
  private final byte[] rpIdHash;

  DefaultWebauthnRelyingParty(
      String id,
      Set<String> origins,
      Set<String> topOrigins,
      WebauthnRelyingParty.CrossOrigin crossOrigin,
      WebauthnRelyingParty.UserVerification userVerification,
      Set<WebauthnAlgorithm> algorithms,
      WebauthnRelyingParty.Attestation attestation,
      WebauthnRelyingParty.SignCountCheck signCountCheck,
      byte[] rpIdHash) {
    this.id = id;
    this.origins = origins;
    this.topOrigins = topOrigins;
    this.crossOrigin = crossOrigin;
    this.userVerification = userVerification;
    this.algorithms = algorithms;
    this.attestation = attestation;
    this.signCountCheck = signCountCheck;
    this.rpIdHash = rpIdHash;
  }

  @Override
  public String id() {
    return id;
  }

  private static final CborReader CBOR = CborReader.builder().maxDepth(16).build();

  @Override
  public WebauthnCredential register(WebauthnRegistration response, byte[] challenge, byte[] userHandle) {
    if (userHandle.length == 0 || userHandle.length > 64) {
      throw new IllegalArgumentException("A user handle must be 1 to 64 bytes: " + userHandle.length);
    }
    byte[] clientDataJson = response.clientDataJsonShared();
    clientData(clientDataJson, "webauthn.create", challenge);

    CborValue value;
    try {
      value = CBOR.read(response.attestationObjectShared());
    } catch (CborParseException e) {
      throw new WebauthnException(WebauthnException.Reason.AUTHENTICATOR_DATA, "The attestation object is not CBOR: " + e.getMessage(), e);
    }
    if (!(value instanceof CborMap object)) {
      throw AuthenticatorData.refuse("The attestation object is not a CBOR map");
    }
    if (!(object.getOrNull("fmt") instanceof CborText fmt)) {
      throw AuthenticatorData.refuse("The attestation object has no \"fmt\" text string");
    }
    if (!(object.getOrNull("attStmt") instanceof CborMap statement)) {
      throw AuthenticatorData.refuse("The attestation object has no \"attStmt\" map");
    }
    if (!(object.getOrNull("authData") instanceof CborBytes authDataBytes)) {
      throw AuthenticatorData.refuse("The attestation object has no \"authData\" byte string");
    }
    AuthenticatorData data = AuthenticatorData.read(authDataBytes.bytes());
    checkCommon(data);
    AuthenticatorData.Attested attested = data.attested();
    if (attested == null) {
      throw AuthenticatorData.refuse("The authenticator data has no attested credential data (the AT flag is not set)");
    }
    checkCredentialId(attested.credentialId());
    CoseKey key = attested.publicKey();
    if (!algorithms.contains(key.algorithm())) {
      throw new WebauthnException(WebauthnException.Reason.PUBLIC_KEY,
          "The credential's algorithm " + key.algorithm() + " is not one this relying party allows: " + names(algorithms));
    }
    String format = fmt.value();
    if (format.equals("none")) {
      if (statement.size() != 0) {
        throw new WebauthnException(WebauthnException.Reason.ATTESTATION, "The \"none\" attestation statement is not empty: " + statement);
      }
    } else if (attestation == Attestation.NONE) {
      throw new WebauthnException(WebauthnException.Reason.ATTESTATION,
          "The attestation format \"" + format + "\" is not \"none\", the only one this relying party accepts");
    }
    return WebauthnCredential.builder(attested.credentialId(), attested.publicKeyCose(), userHandle)
        .signCount(data.signCount())
        .backupEligible(data.has(AuthenticatorData.BE))
        .backedUp(data.has(AuthenticatorData.BS))
        .aaguid(attested.aaguid())
        .attestationFormat(format)
        .build(key);
  }

  @Override
  public WebauthnSignIn signIn(WebauthnAssertion response, byte[] challenge, WebauthnCredential credential) {
    if (!credential.sameId(response.credentialIdShared())) {
      throw new WebauthnException(WebauthnException.Reason.CREDENTIAL_ID, "The response's credential ID is not the stored credential's");
    }
    byte[] handle = response.userHandleSharedOrNull();
    if (handle != null && !credential.sameUserHandle(handle)) {
      throw new WebauthnException(WebauthnException.Reason.USER_HANDLE, "The response's user handle is not the one the credential was registered for");
    }
    byte[] clientDataJson = response.clientDataJsonShared();
    clientData(clientDataJson, "webauthn.get", challenge);
    byte[] authenticatorData = response.authenticatorDataShared();
    AuthenticatorData data = AuthenticatorData.read(authenticatorData);
    if (data.attested() != null) {
      throw AuthenticatorData.refuse("The authenticator data of a sign-in has attested credential data (the AT flag is set)");
    }
    checkCommon(data);
    boolean eligible = data.has(AuthenticatorData.BE);
    if (eligible != credential.backupEligible()) {
      throw new WebauthnException(WebauthnException.Reason.BACKUP,
          "The credential was registered " + (credential.backupEligible() ? "" : "not ") + "backup eligible, and now says it is" + (eligible ? "" : " not"));
    }
    byte[] signed = new byte[authenticatorData.length + 32];
    System.arraycopy(authenticatorData, 0, signed, 0, authenticatorData.length);
    System.arraycopy(sha256(clientDataJson), 0, signed, authenticatorData.length, 32);
    if (!Signatures.verify(credential.key(), signed, response.signatureShared())) {
      throw new WebauthnException(WebauthnException.Reason.SIGNATURE, "The signature does not verify with the credential's " + credential.algorithm() + " key");
    }
    long stored = credential.signCount();
    long now = data.signCount();
    WebauthnSignIn.SignCount count;
    if (stored == 0 && now == 0) {
      count = WebauthnSignIn.SignCount.ZERO;
    } else if (now > stored) {
      count = WebauthnSignIn.SignCount.INCREASED;
    } else {
      if (signCountCheck == SignCountCheck.REFUSE) {
        throw new WebauthnException(WebauthnException.Reason.SIGN_COUNT,
            "The signature counter is " + now + ", not more than the " + stored + " last seen: the authenticator may have been cloned");
      }
      count = WebauthnSignIn.SignCount.NOT_INCREASED;
    }
    return new WebauthnSignIn(credential.seen(Math.max(stored, now), data.has(AuthenticatorData.BS)), data.has(AuthenticatorData.UV), count);
  }

  private void clientData(byte[] json, String type, byte[] challenge) {
    ClientData c = ClientData.read(json);
    if (!c.type().equals(type)) {
      throw new WebauthnException(WebauthnException.Reason.TYPE, "The client data's type is \"" + c.type() + "\", not \"" + type + "\"");
    }
    String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
    if (!MessageDigest.isEqual(c.challenge().getBytes(StandardCharsets.UTF_8), expected.getBytes(StandardCharsets.UTF_8))) {
      throw new WebauthnException(WebauthnException.Reason.CHALLENGE, "The client data's challenge is not the one given");
    }
    if (!origins.contains(c.origin())) {
      throw new WebauthnException(WebauthnException.Reason.ORIGIN,
          "The origin \"" + c.origin() + "\" is not one of this relying party's: " + String.join(", ", origins.stream().sorted().toList()));
    }
    if (c.crossOrigin() && crossOrigin == CrossOrigin.REFUSE) {
      throw new WebauthnException(WebauthnException.Reason.CROSS_ORIGIN, "The response came from a frame of another origin (crossOrigin is true)");
    }
    String top = c.topOrigin();
    if (top != null) {
      if (!c.crossOrigin()) {
        throw new WebauthnException(WebauthnException.Reason.CROSS_ORIGIN, "The client data has a topOrigin, \"" + top + "\", but crossOrigin is not true");
      }
      if (!topOrigins.contains(top)) {
        throw new WebauthnException(WebauthnException.Reason.CROSS_ORIGIN, "The top origin \"" + top + "\" is not one this relying party may be framed in");
      }
    }
  }

  private void checkCommon(AuthenticatorData data) {
    if (!MessageDigest.isEqual(data.rpIdHash(), rpIdHash)) {
      throw new WebauthnException(WebauthnException.Reason.RP_ID, "The authenticator data is for another RP ID than \"" + id + "\"");
    }
    if (!data.has(AuthenticatorData.UP)) {
      throw new WebauthnException(WebauthnException.Reason.USER_PRESENCE, "The user-present flag (UP) is not set");
    }
    if (userVerification == UserVerification.REQUIRED && !data.has(AuthenticatorData.UV)) {
      throw new WebauthnException(WebauthnException.Reason.USER_VERIFICATION, "User verification is required, and the user-verified flag (UV) is not set");
    }
    if (data.has(AuthenticatorData.BS) && !data.has(AuthenticatorData.BE)) {
      throw new WebauthnException(WebauthnException.Reason.BACKUP, "The backed-up flag (BS) is set without the backup-eligible flag (BE)");
    }
  }

  static void checkCredentialId(byte[] id) {
    if (id.length == 0 || id.length > 1023) {
      throw new WebauthnException(WebauthnException.Reason.CREDENTIAL_ID, "A credential ID must be 1 to 1023 bytes: it is " + id.length);
    }
  }

  private static String names(Set<WebauthnAlgorithm> algorithms) {
    return algorithms.stream().sorted().map(Enum::name).collect(Collectors.joining(", "));
  }

  static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("The JDK has no SHA-256", e);
    }
  }
}
