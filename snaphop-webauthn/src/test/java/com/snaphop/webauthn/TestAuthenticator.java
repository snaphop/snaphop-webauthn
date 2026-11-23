package com.snaphop.webauthn;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.function.UnaryOperator;
import org.jspecify.annotations.Nullable;

/// A software authenticator and browser in one, for the tests: makes real
/// keys and signs real ceremonies, every part of which a test can change
/// before or after signing.
final class TestAuthenticator {

  static final String RP_ID = "example.org";
  static final String ORIGIN = "https://example.org";

  static final int UP = 0x01;
  static final int UV = 0x04;
  static final int BE = 0x08;
  static final int BS = 0x10;
  static final int AT = 0x40;
  static final int ED = 0x80;

  /// The kinds of key, each with its algorithm.
  enum Kind {
    ES256(WebauthnAlgorithm.ES256, "secp256r1", 1, 32),
    ES384(WebauthnAlgorithm.ES384, "secp384r1", 2, 48),
    ES512(WebauthnAlgorithm.ES512, "secp521r1", 3, 66),
    ED25519(WebauthnAlgorithm.EDDSA, "Ed25519", 6, 32),
    ED25519_FULLY_SPECIFIED(WebauthnAlgorithm.ED25519, "Ed25519", 6, 32),
    ED448(WebauthnAlgorithm.EDDSA, "Ed448", 7, 57),
    RS256(WebauthnAlgorithm.RS256, "RSA", 0, 0),
    PS256(WebauthnAlgorithm.PS256, "RSA", 0, 0);

    final WebauthnAlgorithm algorithm;
    final String curve;
    final int crv;
    final int size;

    Kind(WebauthnAlgorithm algorithm, String curve, int crv, int size) {
      this.algorithm = algorithm;
      this.curve = curve;
      this.crv = crv;
      this.size = size;
    }
  }

  private static final Map<Kind, KeyPair> KEYS = new EnumMap<>(Kind.class);

  /// One key pair per kind for the whole run: RSA keys are slow to make.
  static synchronized KeyPair keys(Kind kind) {
    return KEYS.computeIfAbsent(kind, k -> {
      try {
        KeyPairGenerator g;
        if (k.curve.equals("RSA")) {
          g = KeyPairGenerator.getInstance("RSA");
          g.initialize(2048);
        } else if (k.curve.startsWith("Ed")) {
          g = KeyPairGenerator.getInstance(k.curve);
        } else {
          g = KeyPairGenerator.getInstance("EC");
          g.initialize(new ECGenParameterSpec(k.curve));
        }
        return g.generateKeyPair();
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException(e);
      }
    });
  }

  /// The COSE key of a kind's key pair, as a map to change before writing.
  static Map<Object, Object> coseKey(Kind kind, KeyPair keys) {
    Map<Object, Object> m = new LinkedHashMap<>();
    switch (kind) {
      case ES256, ES384, ES512 -> {
        ECPublicKey pub = (ECPublicKey) keys.getPublic();
        m.put(1, 2);
        m.put(3, kind.algorithm.coseId());
        m.put(-1, kind.crv);
        m.put(-2, fixed(pub.getW().getAffineX(), kind.size));
        m.put(-3, fixed(pub.getW().getAffineY(), kind.size));
      }
      case ED25519, ED25519_FULLY_SPECIFIED, ED448 -> {
        byte[] spki = keys.getPublic().getEncoded();
        m.put(1, 1);
        m.put(3, kind.algorithm.coseId());
        m.put(-1, kind.crv);
        m.put(-2, Arrays.copyOfRange(spki, spki.length - kind.size, spki.length));
      }
      default -> {
        RSAPublicKey pub = (RSAPublicKey) keys.getPublic();
        m.put(1, 3);
        m.put(3, kind.algorithm.coseId());
        m.put(-1, unsigned(pub.getModulus()));
        m.put(-2, unsigned(pub.getPublicExponent()));
      }
    }
    return m;
  }

  static byte[] fixed(BigInteger v, int size) {
    byte[] b = unsigned(v);
    byte[] out = new byte[size];
    System.arraycopy(b, 0, out, size - b.length, b.length);
    return out;
  }

  static byte[] unsigned(BigInteger v) {
    byte[] b = v.toByteArray();
    return b[0] == 0 && b.length > 1 ? Arrays.copyOfRange(b, 1, b.length) : b;
  }

  static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  static String b64(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  static byte[] sign(Kind kind, KeyPair keys, byte[] data) {
    try {
      Signature s = switch (kind) {
        case ES256 -> Signature.getInstance("SHA256withECDSA");
        case ES384 -> Signature.getInstance("SHA384withECDSA");
        case ES512 -> Signature.getInstance("SHA512withECDSA");
        case ED25519, ED25519_FULLY_SPECIFIED -> Signature.getInstance("Ed25519");
        case ED448 -> Signature.getInstance("Ed448");
        case RS256 -> Signature.getInstance("SHA256withRSA");
        case PS256 -> {
          Signature p = Signature.getInstance("RSASSA-PSS");
          p.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
          yield p;
        }
      };
      s.initSign(keys.getPrivate());
      s.update(data);
      return s.sign();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /// The client data, as a browser writes it, with room for changes.
  static final class ClientDataJson {
    String type;
    String challenge;
    String origin = ORIGIN;
    @Nullable Boolean crossOrigin = false;
    @Nullable String topOrigin;
    /// Written after the members, inside the object, such as `,"origin":"x"`.
    String extra = "";

    ClientDataJson(String type, byte[] challenge) {
      this.type = type;
      this.challenge = b64(challenge);
    }

    byte[] bytes() {
      StringBuilder b = new StringBuilder("{\"type\":\"").append(type)
          .append("\",\"challenge\":\"").append(challenge)
          .append("\",\"origin\":\"").append(origin).append('"');
      if (crossOrigin != null) {
        b.append(",\"crossOrigin\":").append(crossOrigin);
      }
      if (topOrigin != null) {
        b.append(",\"topOrigin\":\"").append(topOrigin).append('"');
      }
      return b.append(extra).append('}').toString().getBytes(StandardCharsets.UTF_8);
    }
  }

  /// A registration, every part of which can be changed before [#build()].
  static final class Registration {
    final Kind kind;
    final KeyPair keys;
    final byte[] challenge;
    final ClientDataJson clientData;
    byte[] rpIdHash = sha256(RP_ID.getBytes(StandardCharsets.UTF_8));
    int flags = UP | UV | AT;
    long signCount;
    byte[] aaguid = new byte[16];
    byte[] credentialId;
    Map<Object, Object> cose;
    /// When set, written in place of the COSE key map.
    byte @Nullable [] coseBytes;
    /// When set, written after the COSE key.
    byte @Nullable [] extensions;
    byte[] trailing = new byte[0];
    String fmt = "none";
    Map<Object, Object> attStmt = new LinkedHashMap<>();
    UnaryOperator<byte[]> authenticatorDataChange = UnaryOperator.identity();
    UnaryOperator<byte[]> attestationObjectChange = UnaryOperator.identity();
    UnaryOperator<byte[]> clientDataChange = UnaryOperator.identity();

    Registration(Kind kind, Random random) {
      this.kind = kind;
      this.keys = keys(kind);
      this.challenge = new byte[32];
      random.nextBytes(challenge);
      this.clientData = new ClientDataJson("webauthn.create", challenge);
      this.credentialId = new byte[16];
      random.nextBytes(credentialId);
      this.cose = coseKey(kind, keys);
    }

    byte[] authenticatorData() {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.writeBytes(rpIdHash);
      out.write(flags);
      for (int i = 3; i >= 0; i--) {
        out.write((int) (signCount >> (8 * i)) & 0xff);
      }
      if ((flags & AT) != 0) {
        out.writeBytes(aaguid);
        out.write(credentialId.length >> 8);
        out.write(credentialId.length & 0xff);
        out.writeBytes(credentialId);
        byte[] key = coseBytes;
        out.writeBytes(key != null ? key : TestCbor.encode(cose));
      }
      byte[] ext = extensions;
      if (ext != null) {
        out.writeBytes(ext);
      }
      out.writeBytes(trailing);
      return authenticatorDataChange.apply(out.toByteArray());
    }

    byte[] attestationObject() {
      Map<Object, Object> o = new LinkedHashMap<>();
      o.put("fmt", fmt);
      o.put("attStmt", attStmt);
      o.put("authData", authenticatorData());
      return attestationObjectChange.apply(TestCbor.encode(o));
    }

    WebauthnRegistration build() {
      return WebauthnRegistration.of(clientDataChange.apply(clientData.bytes()), attestationObject());
    }

    byte[] publicKeyCose() {
      byte[] key = coseBytes;
      return key != null ? key : TestCbor.encode(cose);
    }
  }

  /// A sign-in with the registration's key, every part of which can be
  /// changed before or after signing.
  static final class Assertion {
    final Kind kind;
    final KeyPair keys;
    final byte[] challenge;
    final ClientDataJson clientData;
    byte[] credentialId;
    byte @Nullable [] userHandle;
    byte[] rpIdHash = sha256(RP_ID.getBytes(StandardCharsets.UTF_8));
    int flags = UP | UV;
    long signCount;
    byte @Nullable [] attested;
    byte @Nullable [] extensions;
    byte[] trailing = new byte[0];
    /// Changes what is signed, before signing.
    UnaryOperator<byte[]> authenticatorDataChange = UnaryOperator.identity();
    /// Changes the authenticator data after signing.
    UnaryOperator<byte[]> afterSigning = UnaryOperator.identity();
    UnaryOperator<byte[]> clientDataAfterSigning = UnaryOperator.identity();
    UnaryOperator<byte[]> signatureChange = UnaryOperator.identity();

    Assertion(Registration registration, Random random) {
      this.kind = registration.kind;
      this.keys = registration.keys;
      this.challenge = new byte[32];
      random.nextBytes(challenge);
      this.clientData = new ClientDataJson("webauthn.get", challenge);
      this.credentialId = registration.credentialId.clone();
    }

    WebauthnAssertion build() {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.writeBytes(rpIdHash);
      out.write(flags);
      for (int i = 3; i >= 0; i--) {
        out.write((int) (signCount >> (8 * i)) & 0xff);
      }
      byte[] a = attested;
      if (a != null) {
        out.writeBytes(a);
      }
      byte[] ext = extensions;
      if (ext != null) {
        out.writeBytes(ext);
      }
      out.writeBytes(trailing);
      byte[] authenticatorData = authenticatorDataChange.apply(out.toByteArray());
      byte[] clientDataJson = clientData.bytes();
      byte[] signed = new byte[authenticatorData.length + 32];
      System.arraycopy(authenticatorData, 0, signed, 0, authenticatorData.length);
      System.arraycopy(sha256(clientDataJson), 0, signed, authenticatorData.length, 32);
      byte[] signature = signatureChange.apply(sign(kind, keys, signed));
      return WebauthnAssertion.builder()
          .credentialId(credentialId)
          .clientDataJson(clientDataAfterSigning.apply(clientDataJson))
          .authenticatorData(afterSigning.apply(authenticatorData))
          .signature(signature)
          .userHandle(userHandle)
          .build();
    }
  }
}
