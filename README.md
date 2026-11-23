# snaphop-webauthn

Small Java libraries for checking passkeys (WebAuthn) on a server. Together they are about 76 KB,
and their only runtime dependency is the JDK.

| Library | Module | What it is |
|---------|--------|------------|
| `snaphop-webauthn` | `com.snaphop.webauthn` | Checks passkey registrations and sign-ins (WebAuthn Level 3, sections 7.1 and 7.2) with the JDK's cryptography. A lighter replacement for [webauthn4j](https://github.com/webauthn4j/webauthn4j) and Yubico's [java-webauthn-server](https://github.com/Yubico/java-webauthn-server) when attestation is not needed. 49 KB |
| `snaphop-cbor` | `com.snaphop.cbor` | Reads CBOR (RFC 8949) strictly, with limits for input nobody vouches for. What `snaphop-webauthn` reads authenticator data with. 27 KB |

## Status

Experimental, not yet released. Written for servers that need passkeys without the Jackson, Guava
and reflection the existing libraries bring. To be reviewed before anything depends on it. Expect
the API to change before 1.0.

## Why another one

| | webauthn4j 0.32 | java-webauthn-server 2.10 | snaphop-webauthn |
|---|---|---|---|
| Runtime dependencies | Jackson 3 (databind, CBOR), SLF4J: 3.4 MB | Jackson 2, Guava, PeterO CBOR, Apache HttpClient 5: 9 MB | none (snaphop-cbor): 76 KB |
| Reflection | Jackson databind | Jackson databind | none |
| Attestation | every format, with trust anchors | every format, with trust anchors and the FIDO Metadata Service | none: `none` only, or other formats recorded unverified |

Passkeys from Apple, Google and Microsoft come without attestation, so a site that only wants
passkeys doesn't need the larger part of those libraries.

## Usage

```java
WebauthnRelyingParty rp = WebauthnRelyingParty.builder()
    .id("example.org")
    .origin("https://example.org")
    .build();

// Registering. The challenge and user handle are those in the options given to
// navigator.credentials.create(); the bytes are the response's, base64url-decoded.
WebauthnCredential credential = rp.register(
    WebauthnRegistration.of(clientDataJson, attestationObject), challenge, userHandle);
insertNewCredential(credential.credentialId(), credential.publicKeyCose(), credential.userHandle(),
    credential.signCount(), credential.backupEligible(), credential.backedUp());

// Discoverable sign-in. Look up the stored credential by both the response's
// credential ID and user handle. Refuse a missing handle or record.
WebauthnAssertion assertion = WebauthnAssertion.builder()
    .credentialId(rawId)
    .clientDataJson(clientDataJson)
    .authenticatorData(authenticatorData)
    .signature(signature)
    .userHandle(responseUserHandle)
    .build();
WebauthnCredential stored = WebauthnCredential.builder(credentialId, publicKeyCose, userHandle)
    .signCount(signCount).backupEligible(backupEligible).backedUp(backedUp)
    .build();
WebauthnSignIn signIn = rp.signInDiscoverable(assertion, challenge, stored);
updateIfCurrent(stored, signIn.credential()); // its counter and backup state
```

Anything refused is a `WebauthnException`, with a `reason()` for code and a message for people,
such as `The origin "https://evil.example" is not one of this relying party's: https://example.org`.

The caller reads the browser's JSON and binds each challenge (32 random bytes from
`SecureRandom`) to the ceremony, account when known, and options issued by the server.
Make challenge consumption atomic, use each challenge once, and expire it after a few minutes.
Insert new credentials with a unique constraint on credential ID across accounts for the RP.
Update the stored counter and backup state conditionally on the credential state used for
verification, or serialize verification and updates for each credential.

For a sign-in initiated for an identified account, call `signIn` with a credential selected
from that account and any `allowCredentials` in the request. The response may omit the user
handle in that flow. For conditional registration, pass `RegistrationMediation.CONDITIONAL`
only when the server's original request used conditional mediation.

## What it checks

The verifier handles client data, authenticator data, credential keys, and assertion signatures.
The caller completes the account and storage steps above.

- **The client data** must be UTF-8 JSON with nothing after it and no member twice (two `origin`
  members could be read differently by two parsers). The challenge is compared as the exact
  base64url text, origins exactly, `crossOrigin` and `topOrigin` against what the relying party
  allows. When a top-origin allowlist is configured, cross-origin responses must supply a
  matching `topOrigin`.
- **The authenticator data's** flags must agree with what follows: attested credential data
  exactly when AT is set (never in a sign-in), extensions exactly when ED is set, nothing after the
  last part. A credential can't be backed up without being backup eligible, and its eligibility
  can't change.
- **Credential public keys** (COSE): the algorithm must go with the key type and curve,
  coordinates must be the curve's size, below its prime and on the curve, RSA moduli at least
  2048 bits. New credentials use canonical CBOR and contain only the required public key
  parameters and `alg`.
- **Signatures**: ECDSA signatures must be strict DER with r and s from 1 to n - 1 (what
  CVE-2022-21449 let through), before the JDK checks them. EdDSA signatures must be their exact
  length.
- **The signature counter** must go up, unless it stays at 0 (passkeys that sync don't count).
- **CBOR** must be well-formed and valid: text is UTF-8, no map has a key twice (including keys
  written two ways), nesting and lengths are limited before anything is allocated.

Algorithms: ES256, ES384, ES512, EdDSA (Ed25519 and Ed448), Ed25519, Ed448, RS256 and PS256.

## How it is tested

- **The WebAuthn Level 3 test vectors**: all fifteen registration and sign-in ceremonies of
  section 16 (every algorithm, every attestation format, cross-origin, a 1023-byte credential ID).
- **A software authenticator** in the tests makes real ceremonies for every key type, then about a
  hundred changes to them, each refused for its reason with its exact message.
- **Oracles**: selected ceremonies and changes are also checked by webauthn4j and java-webauthn-server.
  What this library accepts, both of them accept; where they differ, each case is listed with
  why. In every one of them this library refuses and an oracle accepts. Some examples:
  - both oracles register a key whose point is not on its curve;
  - both oracles register a key whose algorithm doesn't go with its curve;
  - java-webauthn-server ignores `crossOrigin`, `topOrigin`, text after the client data, and bytes
    after a sign-in's authenticator data;
  - webauthn4j keeps the last of a COSE key's members written twice.
- **JavaScript reference**: SimpleWebAuthn verifies the same registration and assertion bytes
  on Node in the test module. CI requires this comparison, including stored credential values
  and representative refusal cases.
- **Damage**: thousands of real ceremonies with random damage (a bit flipped, a byte changed,
  added, taken out, cut short). This library only ever refuses with a `WebauthnException`, and
  never accepts what an oracle refuses.
- **CBOR**: RFC 8949's examples (Appendix A read as its diagnostic notation, Appendix F's 94
  not-well-formed items refused), random values written every legal way, and damaged encodings,
  all read the same by PeterO's CBOR (java-webauthn-server's).
- **Mutation testing** with PIT on both libraries (see [development.md](development.md)):
  snaphop-cbor kills 98% of its mutants, snaphop-webauthn 94%. Most survivors are in the strict
  DER check, where the JDK refuses the same signatures, so removing ours changes nothing today;
  it stays for the day the JDK accepts one it shouldn't.

## Building

```
./mvnw verify
```

See [development.md](development.md).

## License

[Zero-Clause BSD](LICENSE).
