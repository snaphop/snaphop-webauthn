package com.snaphop.webauthn;

/// A sign-in [WebauthnRelyingParty] accepted.
///
/// @param credential the credential with its counter and backup state
///     brought up to date: store it in place of the old one
/// @param userVerified whether the authenticator verified the user
///     (biometrics or a PIN): the UV flag
/// @param signCount what the signature counter did
public record WebauthnSignIn(WebauthnCredential credential, boolean userVerified, SignCount signCount) {

  /// What the signature counter did since the credential was last seen.
  public enum SignCount {
    /// It went up, as it should for an authenticator that counts.
    INCREASED,
    /// Both the old and the new are 0: an authenticator that doesn't count,
    /// as passkeys that sync don't.
    ZERO,
    /// It stayed the same or went down, which can mean the authenticator
    /// was cloned. Returned only when the relying party is set to
    /// [WebauthnRelyingParty.SignCountCheck#REPORT]; otherwise it is refused.
    NOT_INCREASED
  }
}
