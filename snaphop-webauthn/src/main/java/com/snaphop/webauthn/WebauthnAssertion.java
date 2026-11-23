package com.snaphop.webauthn;

import java.util.Objects;
import org.jspecify.annotations.Nullable;

/// What the browser returns from `navigator.credentials.get()`: the
/// credential's `rawId`, and its `response`, an
/// `AuthenticatorAssertionResponse`.
///
/// Its byte strings are what the browser's `toJSON()` sends as base64url
/// (decode them with `Base64.getUrlDecoder()`). Immutable: the bytes are
/// copied in and out.
public final class WebauthnAssertion {

  private final byte[] credentialId;
  private final byte[] clientDataJson;
  private final byte[] authenticatorData;
  private final byte[] signature;
  private final byte @Nullable [] userHandle;

  private WebauthnAssertion(Builder b) {
    this.credentialId = Objects.requireNonNull(b.credentialId, "credentialId").clone();
    this.clientDataJson = Objects.requireNonNull(b.clientDataJson, "clientDataJson").clone();
    this.authenticatorData = Objects.requireNonNull(b.authenticatorData, "authenticatorData").clone();
    this.signature = Objects.requireNonNull(b.signature, "signature").clone();
    byte[] handle = b.userHandle;
    this.userHandle = handle == null ? null : handle.clone();
  }

  /// A new builder.
  ///
  /// @return the builder
  public static Builder builder() {
    return new Builder();
  }

  /// A copy of the credential's `rawId`.
  ///
  /// @return the credential ID
  public byte[] credentialId() {
    return credentialId.clone();
  }

  /// A copy of `response.clientDataJSON`.
  ///
  /// @return the client data, UTF-8 JSON
  public byte[] clientDataJson() {
    return clientDataJson.clone();
  }

  /// A copy of `response.authenticatorData`.
  ///
  /// @return the authenticator data
  public byte[] authenticatorData() {
    return authenticatorData.clone();
  }

  /// A copy of `response.signature`.
  ///
  /// @return the signature
  public byte[] signature() {
    return signature.clone();
  }

  /// A copy of `response.userHandle`, or null when the browser sent none.
  ///
  /// @return the user handle, or null
  public byte @Nullable [] userHandleOrNull() {
    byte[] handle = userHandle;
    return handle == null ? null : handle.clone();
  }

  byte[] credentialIdShared() {
    return credentialId;
  }

  byte[] clientDataJsonShared() {
    return clientDataJson;
  }

  byte[] authenticatorDataShared() {
    return authenticatorData;
  }

  byte[] signatureShared() {
    return signature;
  }

  byte @Nullable [] userHandleSharedOrNull() {
    return userHandle;
  }

  /// Builds a [WebauthnAssertion]. Everything but the user handle is
  /// required.
  public static final class Builder {

    private byte @Nullable [] credentialId;
    private byte @Nullable [] clientDataJson;
    private byte @Nullable [] authenticatorData;
    private byte @Nullable [] signature;
    private byte @Nullable [] userHandle;

    private Builder() {}

    /// The credential's `rawId`.
    ///
    /// @param credentialId the credential ID
    /// @return this builder
    public Builder credentialId(byte[] credentialId) {
      this.credentialId = credentialId.clone();
      return this;
    }

    /// `response.clientDataJSON`.
    ///
    /// @param clientDataJson the client data
    /// @return this builder
    public Builder clientDataJson(byte[] clientDataJson) {
      this.clientDataJson = clientDataJson.clone();
      return this;
    }

    /// `response.authenticatorData`.
    ///
    /// @param authenticatorData the authenticator data
    /// @return this builder
    public Builder authenticatorData(byte[] authenticatorData) {
      this.authenticatorData = authenticatorData.clone();
      return this;
    }

    /// `response.signature`.
    ///
    /// @param signature the signature
    /// @return this builder
    public Builder signature(byte[] signature) {
      this.signature = signature.clone();
      return this;
    }

    /// `response.userHandle`, or null (the default) when the browser sent
    /// none.
    ///
    /// @param userHandle the user handle, or null
    /// @return this builder
    public Builder userHandle(byte @Nullable [] userHandle) {
      this.userHandle = userHandle == null ? null : userHandle.clone();
      return this;
    }

    /// The assertion.
    ///
    /// @return the assertion
    /// @throws NullPointerException if a required part is missing
    public WebauthnAssertion build() {
      return new WebauthnAssertion(this);
    }
  }
}
