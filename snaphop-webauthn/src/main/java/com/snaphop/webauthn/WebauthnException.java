package com.snaphop.webauthn;

import java.io.Serial;

/// A registration or sign-in that [WebauthnRelyingParty] refused.
///
/// [#reason()] is for code; the message is for people and logs, such as
/// `The origin "https://evil.example" is not one of this relying party's: https://example.org`.
/// Nothing in a message is secret: it may name origins, flags and lengths,
/// never keys.
public final class WebauthnException extends RuntimeException {

  @Serial private static final long serialVersionUID = 1L;

  /// Why it was refused.
  private final Reason reason;

  WebauthnException(Reason reason, String message) {
    super(message);
    this.reason = reason;
  }

  WebauthnException(Reason reason, String message, Throwable cause) {
    super(message, cause);
    this.reason = reason;
  }

  /// Why it was refused.
  ///
  /// @return the reason
  public Reason reason() {
    return reason;
  }

  /// Why a response was refused, by the step of the WebAuthn Level 3
  /// ceremony that refused it.
  public enum Reason {
    /// The client data is not JSON, or lacks a member, or has one twice.
    CLIENT_DATA,
    /// The client data's `type` is not `webauthn.create` (registering) or
    /// `webauthn.get` (signing in).
    TYPE,
    /// The client data's `challenge` is not the one given.
    CHALLENGE,
    /// The client data's `origin` is not one of the relying party's.
    ORIGIN,
    /// The response came from inside a frame (`crossOrigin`) the relying
    /// party does not allow, or from a top origin it does not list.
    CROSS_ORIGIN,
    /// The attestation object or authenticator data is not what the
    /// specification says it is: not CBOR, too short, too long, flags
    /// that contradict what follows.
    AUTHENTICATOR_DATA,
    /// The authenticator data is for another RP ID.
    RP_ID,
    /// The user-present flag is not set.
    USER_PRESENCE,
    /// User verification is required and the user-verified flag is not set.
    USER_VERIFICATION,
    /// The backup flags are impossible (backed up but not eligible), or
    /// the credential's eligibility changed since it was registered.
    BACKUP,
    /// The credential's public key is not a COSE key this library reads, or
    /// its algorithm is not one the relying party allows.
    PUBLIC_KEY,
    /// The attestation statement's format is not one the relying party
    /// accepts.
    ATTESTATION,
    /// The credential ID is empty, too long, or not the stored credential's.
    CREDENTIAL_ID,
    /// The user handle is not the stored credential's.
    USER_HANDLE,
    /// The signature does not verify.
    SIGNATURE,
    /// The signature counter did not increase, which can mean the
    /// authenticator was cloned.
    SIGN_COUNT
  }
}
