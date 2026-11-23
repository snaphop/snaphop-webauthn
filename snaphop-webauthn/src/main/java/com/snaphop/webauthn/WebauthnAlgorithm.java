package com.snaphop.webauthn;

import org.jspecify.annotations.Nullable;

/// The signature algorithms a credential's key may use, by their COSE
/// identifiers (the IANA COSE Algorithms registry).
///
/// Browsers ask for the ones a relying party lists in
/// `pubKeyCredParams`; passkeys from Apple, Google and Microsoft use
/// [#ES256], and some security keys [#EDDSA]. Windows Hello may use
/// [#RS256].
public enum WebauthnAlgorithm {
  /// ECDSA on P-256 with SHA-256, COSE `-7`.
  ES256(-7),
  /// ECDSA on P-384 with SHA-384, COSE `-35`.
  ES384(-35),
  /// ECDSA on P-521 with SHA-512, COSE `-36`.
  ES512(-36),
  /// EdDSA, COSE `-8`: Ed25519 or Ed448, by the key's curve.
  EDDSA(-8),
  /// Ed25519, COSE `-19` (fully specified).
  ED25519(-19),
  /// RSASSA-PKCS1-v1_5 with SHA-256, COSE `-257`.
  RS256(-257),
  /// RSASSA-PSS with SHA-256, COSE `-37`.
  PS256(-37);

  private final int coseId;

  WebauthnAlgorithm(int coseId) {
    this.coseId = coseId;
  }

  /// The COSE identifier, as in `pubKeyCredParams`' `alg`.
  ///
  /// @return the identifier, such as `-7`
  public int coseId() {
    return coseId;
  }

  /// The algorithm with a COSE identifier, or null for one this library
  /// does not check.
  ///
  /// @param coseId the identifier
  /// @return the algorithm, or null
  public static @Nullable WebauthnAlgorithm ofCoseIdOrNull(long coseId) {
    for (WebauthnAlgorithm a : values()) {
      if (a.coseId == coseId) {
        return a;
      }
    }
    return null;
  }
}
