package com.snaphop.webauthn;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import org.jspecify.annotations.Nullable;

/// Verifies a signature with the JDK, after checking its shape ourselves:
/// ECDSA signatures must be strict DER with r and s from 1 to n - 1
/// (refusing what CVE-2022-21449 let through), EdDSA signatures their
/// exact length.
final class Signatures {

  private Signatures() {}

  static boolean verify(CoseKey key, byte[] data, byte[] signature) {
    try {
      return switch (key.algorithm()) {
        case ES256 -> ecdsa(key, "SHA256withECDSA", data, signature);
        case ES384 -> ecdsa(key, "SHA384withECDSA", data, signature);
        case ES512 -> ecdsa(key, "SHA512withECDSA", data, signature);
        case EDDSA, ED25519 -> eddsa(key, data, signature);
        case RS256 -> jdk(key, Signature.getInstance("SHA256withRSA"), data, signature);
        case PS256 -> {
          Signature s = Signature.getInstance("RSASSA-PSS");
          s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC));
          yield jdk(key, s, data, signature);
        }
      };
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  private static boolean ecdsa(CoseKey key, String name, byte[] data, byte[] signature) throws GeneralSecurityException {
    BigInteger n = ((ECPublicKey) key.publicKey()).getParams().getOrder();
    if (!strictDer(signature, n)) {
      return false;
    }
    return jdk(key, Signature.getInstance(name), data, signature);
  }

  private static boolean eddsa(CoseKey key, byte[] data, byte[] signature) throws GeneralSecurityException {
    int length = key.curve() == CoseKey.Curve.ED25519 ? 64 : 114;
    if (signature.length != length) {
      return false;
    }
    return jdk(key, Signature.getInstance(key.curve().jdkName), data, signature);
  }

  private static boolean jdk(CoseKey key, Signature s, byte[] data, byte[] signature) throws GeneralSecurityException {
    s.initVerify(key.publicKey());
    s.update(data);
    return s.verify(signature);
  }

  /// `SEQUENCE { INTEGER r, INTEGER s }` in DER: definite, minimal lengths,
  /// minimal positive integers, nothing after, and 1 <= r, s < n.
  static boolean strictDer(byte[] sig, BigInteger n) {
    Der d = new Der(sig);
    if (d.next() != 0x30) {
      return false;
    }
    int length = d.length();
    if (length < 0 || d.pos + length != sig.length) {
      return false;
    }
    @Nullable BigInteger r = d.integer();
    @Nullable BigInteger s = r == null ? null : d.integer();
    if (r == null || s == null || d.pos != sig.length) {
      return false;
    }
    return r.signum() > 0 && s.signum() > 0 && r.compareTo(n) < 0 && s.compareTo(n) < 0;
  }

  private static final class Der {
    final byte[] in;
    int pos;

    Der(byte[] in) {
      this.in = in;
    }

    int next() {
      return pos < in.length ? in[pos++] & 0xff : -1;
    }

    /// A DER length: short form, or long form in as few bytes as it needs
    /// (and only when the short form can't hold it). -1 when not.
    int length() {
      int first = next();
      if (first < 0) {
        return -1;
      }
      if (first < 0x80) {
        return first;
      }
      int count = first & 0x7f;
      if (count == 0 || count > 2) {
        return -1;
      }
      int value = 0;
      for (int i = 0; i < count; i++) {
        int b = next();
        if (b < 0 || (i == 0 && b == 0)) {
          return -1;
        }
        value = (value << 8) | b;
      }
      return value < 0x80 ? -1 : value;
    }

    @Nullable BigInteger integer() {
      if (next() != 0x02) {
        return null;
      }
      int length = length();
      if (length <= 0 || pos + length > in.length) {
        return null;
      }
      int first = in[pos] & 0xff;
      if (first >= 0x80) {
        return null;
      }
      if (first == 0 && length > 1 && (in[pos + 1] & 0xff) < 0x80) {
        return null;
      }
      BigInteger value = new BigInteger(1, Arrays.copyOfRange(in, pos, pos + length));
      pos += length;
      return value;
    }
  }
}
