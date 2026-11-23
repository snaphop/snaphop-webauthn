package com.snaphop.webauthn;

import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/// A registered credential: what a relying party stores, and gives back
/// to [WebauthnRelyingParty#signIn(WebauthnAssertion, byte[], WebauthnCredential)].
///
/// [WebauthnRelyingParty#register(WebauthnRegistration, byte[], byte[])] makes
/// one; [#builder(byte[], byte[], byte[])] makes one again from storage.
/// Store at least the credential ID, the public key, the user handle, the
/// signature counter and the backup flags. A sign-in returns the credential
/// with its counter and backup state brought up to date
/// ([WebauthnSignIn#credential()]): store that.
///
/// Immutable: the bytes are copied in and out.
public final class WebauthnCredential {

  private final byte[] credentialId;
  private final byte[] publicKeyCose;
  private final byte[] userHandle;
  private final long signCount;
  private final boolean backupEligible;
  private final boolean backedUp;
  private final UUID aaguid;
  private final String attestationFormat;
  private final CoseKey key;

  private WebauthnCredential(Builder b, CoseKey key) {
    this.credentialId = b.credentialId;
    this.publicKeyCose = b.publicKeyCose;
    this.userHandle = b.userHandle;
    this.signCount = b.signCount;
    this.backupEligible = b.backupEligible;
    this.backedUp = b.backedUp;
    this.aaguid = b.aaguid;
    this.attestationFormat = b.attestationFormat;
    this.key = key;
  }

  /// A builder, to make a stored credential again. The others default to a
  /// counter of 0, not backup eligible, not backed up, an all-zero AAGUID
  /// and the attestation format `none`.
  ///
  /// @param credentialId the credential ID
  /// @param publicKeyCose the public key, as [#publicKeyCose()] gave it
  /// @param userHandle the user handle it was registered for
  /// @return the builder
  public static Builder builder(byte[] credentialId, byte[] publicKeyCose, byte[] userHandle) {
    return new Builder(credentialId, publicKeyCose, userHandle);
  }

  /// A copy of the credential ID.
  ///
  /// @return the credential ID, 1 to 1023 bytes
  public byte[] credentialId() {
    return credentialId.clone();
  }

  /// A copy of the public key as a COSE key (CBOR), exactly as the
  /// authenticator wrote it.
  ///
  /// @return the COSE key
  public byte[] publicKeyCose() {
    return publicKeyCose.clone();
  }

  /// A copy of the user handle: the `user.id` the credential was
  /// registered for.
  ///
  /// @return the user handle
  public byte[] userHandle() {
    return userHandle.clone();
  }

  /// The key's algorithm.
  ///
  /// @return the algorithm
  public WebauthnAlgorithm algorithm() {
    return key.algorithm();
  }

  /// The signature counter last seen. Passkeys that sync, such as Apple's
  /// and Google's, always say 0.
  ///
  /// @return the counter, 0 to 2^32 - 1
  public long signCount() {
    return signCount;
  }

  /// Whether the credential may be backed up (synced): the BE flag at
  /// registration, which never changes.
  ///
  /// @return true for a passkey that can sync
  public boolean backupEligible() {
    return backupEligible;
  }

  /// Whether the credential was backed up when last seen: the BS flag.
  ///
  /// @return true when backed up
  public boolean backedUp() {
    return backedUp;
  }

  /// The authenticator's model, as it said at registration; all zeros when
  /// it said nothing, as passkeys usually do. Not checked: anyone can write
  /// any AAGUID without attestation.
  ///
  /// @return the AAGUID
  public UUID aaguid() {
    return aaguid;
  }

  /// The attestation statement's format at registration, such as `none` or
  /// `packed`. Not checked (see [WebauthnRelyingParty.Attestation]).
  ///
  /// @return the format
  public String attestationFormat() {
    return attestationFormat;
  }

  CoseKey key() {
    return key;
  }

  boolean sameId(byte[] id) {
    return java.security.MessageDigest.isEqual(credentialId, id);
  }

  boolean sameUserHandle(byte[] handle) {
    return java.security.MessageDigest.isEqual(userHandle, handle);
  }

  WebauthnCredential seen(long newSignCount, boolean newBackedUp) {
    Builder b = new Builder(credentialId, publicKeyCose, userHandle)
        .signCount(newSignCount)
        .backupEligible(backupEligible)
        .backedUp(newBackedUp)
        .aaguid(aaguid)
        .attestationFormat(attestationFormat);
    return new WebauthnCredential(b, key);
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof WebauthnCredential c
        && Arrays.equals(credentialId, c.credentialId)
        && Arrays.equals(publicKeyCose, c.publicKeyCose)
        && Arrays.equals(userHandle, c.userHandle)
        && signCount == c.signCount
        && backupEligible == c.backupEligible
        && backedUp == c.backedUp
        && aaguid.equals(c.aaguid)
        && attestationFormat.equals(c.attestationFormat);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(credentialId);
  }

  @Override
  public String toString() {
    return "WebauthnCredential[" + key.algorithm() + ", " + credentialId.length + "-byte ID, signCount " + signCount
        + (backupEligible ? ", backup eligible" : "") + (backedUp ? ", backed up" : "") + "]";
  }

  /// Makes a [WebauthnCredential] again from storage.
  public static final class Builder {

    private final byte[] credentialId;
    private final byte[] publicKeyCose;
    private final byte[] userHandle;
    private long signCount;
    private boolean backupEligible;
    private boolean backedUp;
    private UUID aaguid = new UUID(0, 0);
    private String attestationFormat = "none";

    private Builder(byte[] credentialId, byte[] publicKeyCose, byte[] userHandle) {
      this.credentialId = credentialId.clone();
      this.publicKeyCose = publicKeyCose.clone();
      this.userHandle = userHandle.clone();
    }

    /// The signature counter last seen, 0 until set.
    ///
    /// @param signCount 0 to 2^32 - 1
    /// @return this builder
    /// @throws IllegalArgumentException outside that range
    public Builder signCount(long signCount) {
      if (signCount < 0 || signCount > 0xffff_ffffL) {
        throw new IllegalArgumentException("signCount must be 0 to 2^32 - 1: " + signCount);
      }
      this.signCount = signCount;
      return this;
    }

    /// Whether it may be backed up (the BE flag at registration), false
    /// until set.
    ///
    /// @param backupEligible the flag
    /// @return this builder
    public Builder backupEligible(boolean backupEligible) {
      this.backupEligible = backupEligible;
      return this;
    }

    /// Whether it was backed up when last seen (the BS flag), false until
    /// set.
    ///
    /// @param backedUp the flag
    /// @return this builder
    public Builder backedUp(boolean backedUp) {
      this.backedUp = backedUp;
      return this;
    }

    /// The authenticator's model, all zeros until set.
    ///
    /// @param aaguid the AAGUID
    /// @return this builder
    public Builder aaguid(UUID aaguid) {
      this.aaguid = Objects.requireNonNull(aaguid);
      return this;
    }

    /// The attestation format at registration, `none` until set.
    ///
    /// @param attestationFormat the format
    /// @return this builder
    public Builder attestationFormat(String attestationFormat) {
      this.attestationFormat = Objects.requireNonNull(attestationFormat);
      return this;
    }

    /// The credential. Reads and checks the public key again.
    ///
    /// @return the credential
    /// @throws WebauthnException ([WebauthnException.Reason#PUBLIC_KEY]) if
    ///     the key can't be read, or ([WebauthnException.Reason#CREDENTIAL_ID])
    ///     if the ID is empty or longer than 1023 bytes, or
    ///     ([WebauthnException.Reason#BACKUP]) if backed up but not eligible
    /// @throws IllegalArgumentException if the user handle is empty or longer
    ///     than 64 bytes
    public WebauthnCredential build() {
      DefaultWebauthnRelyingParty.checkCredentialId(credentialId);
      if (userHandle.length == 0 || userHandle.length > 64) {
        throw new IllegalArgumentException("A user handle must be 1 to 64 bytes: " + userHandle.length);
      }
      if (backedUp && !backupEligible) {
        throw new WebauthnException(WebauthnException.Reason.BACKUP, "A credential can't be backed up without being backup eligible");
      }
      return new WebauthnCredential(this, CoseKey.read(publicKeyCose));
    }

    WebauthnCredential build(CoseKey key) {
      return new WebauthnCredential(this, key);
    }
  }
}
