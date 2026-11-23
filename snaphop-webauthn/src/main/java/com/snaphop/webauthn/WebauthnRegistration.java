package com.snaphop.webauthn;

/// What the browser returns from `navigator.credentials.create()`: the
/// `response` of the `PublicKeyCredential`, an `AuthenticatorAttestationResponse`.
///
/// Its two byte strings are what the browser's `toJSON()` sends as base64url
/// (decode them with `Base64.getUrlDecoder()`). Immutable: the bytes are
/// copied in and out.
public final class WebauthnRegistration {

  private final byte[] clientDataJson;
  private final byte[] attestationObject;

  private WebauthnRegistration(byte[] clientDataJson, byte[] attestationObject) {
    this.clientDataJson = clientDataJson.clone();
    this.attestationObject = attestationObject.clone();
  }

  /// A registration response.
  ///
  /// @param clientDataJson `response.clientDataJSON`
  /// @param attestationObject `response.attestationObject`
  /// @return the response
  public static WebauthnRegistration of(byte[] clientDataJson, byte[] attestationObject) {
    return new WebauthnRegistration(clientDataJson, attestationObject);
  }

  /// A copy of `response.clientDataJSON`.
  ///
  /// @return the client data, UTF-8 JSON
  public byte[] clientDataJson() {
    return clientDataJson.clone();
  }

  /// A copy of `response.attestationObject`.
  ///
  /// @return the attestation object, CBOR
  public byte[] attestationObject() {
    return attestationObject.clone();
  }

  byte[] clientDataJsonShared() {
    return clientDataJson;
  }

  byte[] attestationObjectShared() {
    return attestationObject;
  }
}
