package com.snaphop.webauthn;

import com.snaphop.cbor.CborBytes;
import com.snaphop.cbor.CborInteger;
import com.snaphop.cbor.CborMap;
import com.snaphop.cbor.CborParseException;
import com.snaphop.cbor.CborReader;
import com.snaphop.cbor.CborValue;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import org.jspecify.annotations.Nullable;

/// A credential public key, read from its COSE_Key (RFC 9052, RFC 9053)
/// and checked: the key type, curve and algorithm agree, coordinates are
/// the curve's size and the point is on the curve, RSA moduli are at least
/// 2048 bits.
record CoseKey(WebauthnAlgorithm algorithm, PublicKey publicKey, Curve curve) {

  static final CborReader CBOR = CborReader.builder().maxDepth(16).build();

  /// The curve, or NONE for RSA.
  enum Curve {
    P256("secp256r1", 32),
    P384("secp384r1", 48),
    P521("secp521r1", 66),
    ED25519("Ed25519", 32),
    ED448("Ed448", 57),
    NONE("", 0);

    final String jdkName;
    final int size;

    Curve(String jdkName, int size) {
      this.jdkName = jdkName;
      this.size = size;
    }
  }

  private static final int KTY = 1;
  private static final int ALG = 3;
  private static final int CRV_OR_N = -1;
  private static final int X_OR_E = -2;
  private static final int Y = -3;

  private static final int KTY_OKP = 1;
  private static final int KTY_EC2 = 2;
  private static final int KTY_RSA = 3;

  private static final byte[] ED25519_SPKI = HexFormat.of().parseHex("302a300506032b6570032100");
  private static final byte[] ED448_SPKI = HexFormat.of().parseHex("3043300506032b6571033a00");

  static CoseKey read(byte[] cose) {
    CborValue value;
    try {
      value = CBOR.read(cose);
    } catch (CborParseException e) {
      throw refuse("The credential public key is not CBOR: " + e.getMessage(), e);
    }
    return read(value);
  }

  static CoseKey read(CborValue value) {
    if (!(value instanceof CborMap map)) {
      throw refuse("The credential public key is not a COSE key (a CBOR map): " + value.getClass().getSimpleName());
    }
    long kty = integer(map, KTY, "kty (1)");
    long alg = integer(map, ALG, "alg (3)");
    WebauthnAlgorithm algorithm = WebauthnAlgorithm.ofCoseIdOrNull(alg);
    if (algorithm == null) {
      throw refuse("The credential public key's algorithm " + alg + " is not one this library checks");
    }
    if (kty == KTY_EC2) {
      return ec2(map, algorithm);
    } else if (kty == KTY_OKP) {
      return okp(map, algorithm);
    } else if (kty == KTY_RSA) {
      return rsa(map, algorithm);
    }
    throw refuse("The credential public key's key type " + kty + " is not one this library reads (1 OKP, 2 EC2, 3 RSA)");
  }

  private static CoseKey ec2(CborMap map, WebauthnAlgorithm algorithm) {
    long crv = integer(map, CRV_OR_N, "crv (-1)");
    Curve curve;
    if (crv == 1) {
      curve = Curve.P256;
    } else if (crv == 2) {
      curve = Curve.P384;
    } else if (crv == 3) {
      curve = Curve.P521;
    } else {
      throw refuse("The credential public key's EC2 curve " + crv + " is not one this library reads (1 P-256, 2 P-384, 3 P-521)");
    }
    WebauthnAlgorithm expected = switch (curve) {
      case P256 -> WebauthnAlgorithm.ES256;
      case P384 -> WebauthnAlgorithm.ES384;
      default -> WebauthnAlgorithm.ES512;
    };
    if (algorithm != expected) {
      throw refuse("The credential public key's algorithm " + algorithm + " does not go with its curve " + curve + " (" + expected + " does)");
    }
    byte[] x = bytes(map, X_OR_E, "x (-2)");
    byte[] y = bytes(map, Y, "y (-3)");
    if (x.length != curve.size || y.length != curve.size) {
      throw refuse("The credential public key's coordinates must be " + curve.size + " bytes for " + curve + ": x is " + x.length + ", y is " + y.length);
    }
    try {
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
      parameters.init(new ECGenParameterSpec(curve.jdkName));
      ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
      BigInteger bx = new BigInteger(1, x);
      BigInteger by = new BigInteger(1, y);
      onCurve(spec.getCurve(), bx, by, curve);
      PublicKey key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(bx, by), spec));
      return new CoseKey(algorithm, key, curve);
    } catch (GeneralSecurityException e) {
      throw refuse("The credential public key is not a usable " + curve + " key: " + e.getMessage(), e);
    }
  }

  private static void onCurve(EllipticCurve c, BigInteger x, BigInteger y, Curve curve) {
    BigInteger p = ((ECFieldFp) c.getField()).getP();
    if (x.compareTo(p) >= 0 || y.compareTo(p) >= 0) {
      throw refuse("The credential public key's coordinates are not less than " + curve + "'s prime");
    }
    BigInteger left = y.multiply(y).mod(p);
    BigInteger right = x.pow(3).add(c.getA().multiply(x)).add(c.getB()).mod(p);
    if (!left.equals(right)) {
      throw refuse("The credential public key's point is not on " + curve);
    }
  }

  private static CoseKey okp(CborMap map, WebauthnAlgorithm algorithm) {
    long crv = integer(map, CRV_OR_N, "crv (-1)");
    Curve curve;
    byte[] prefix;
    if (crv == 6) {
      curve = Curve.ED25519;
      prefix = ED25519_SPKI;
    } else if (crv == 7) {
      curve = Curve.ED448;
      prefix = ED448_SPKI;
    } else {
      throw refuse("The credential public key's OKP curve " + crv + " is not one this library reads (6 Ed25519, 7 Ed448)");
    }
    boolean fits = algorithm == WebauthnAlgorithm.EDDSA
        || (algorithm == WebauthnAlgorithm.ED25519 && curve == Curve.ED25519)
        || (algorithm == WebauthnAlgorithm.ED448 && curve == Curve.ED448);
    if (!fits) {
      throw refuse("The credential public key's algorithm " + algorithm + " does not go with its curve " + curve);
    }
    byte[] x = bytes(map, X_OR_E, "x (-2)");
    if (x.length != curve.size) {
      throw refuse("The credential public key must be " + curve.size + " bytes for " + curve + ": it is " + x.length);
    }
    byte[] spki = Arrays.copyOf(prefix, prefix.length + x.length);
    System.arraycopy(x, 0, spki, prefix.length, x.length);
    try {
      PublicKey key = KeyFactory.getInstance(curve.jdkName).generatePublic(new X509EncodedKeySpec(spki));
      return new CoseKey(algorithm, key, curve);
    } catch (GeneralSecurityException e) {
      throw refuse("The credential public key is not a usable " + curve + " key: " + e.getMessage(), e);
    }
  }

  private static CoseKey rsa(CborMap map, WebauthnAlgorithm algorithm) {
    if (algorithm != WebauthnAlgorithm.RS256 && algorithm != WebauthnAlgorithm.PS256) {
      throw refuse("The credential public key's algorithm " + algorithm + " does not go with an RSA key");
    }
    BigInteger n = new BigInteger(1, bytes(map, CRV_OR_N, "n (-1)"));
    BigInteger e = new BigInteger(1, bytes(map, X_OR_E, "e (-2)"));
    if (n.bitLength() < 2048) {
      throw refuse("The credential public key's RSA modulus is " + n.bitLength() + " bits, less than 2048");
    }
    if (!e.testBit(0) || e.compareTo(BigInteger.valueOf(3)) < 0 || e.compareTo(n) >= 0) {
      throw refuse("The credential public key's RSA exponent is not an odd number from 3 to below the modulus");
    }
    try {
      PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
      return new CoseKey(algorithm, key, Curve.NONE);
    } catch (GeneralSecurityException ex) {
      throw refuse("The credential public key is not a usable RSA key: " + ex.getMessage(), ex);
    }
  }

  private static long integer(CborMap map, long key, String name) {
    CborValue v = map.getOrNull(key);
    if (v == null) {
      throw refuse("The credential public key has no " + name);
    }
    if (!(v instanceof CborInteger i)) {
      throw refuse("The credential public key's " + name + " is not an integer: " + v);
    }
    try {
      return i.longValueExact();
    } catch (ArithmeticException e) {
      throw refuse("The credential public key's " + name + " is out of range: " + v, e);
    }
  }

  private static byte[] bytes(CborMap map, long key, String name) {
    @Nullable CborValue v = map.getOrNull(key);
    if (v == null) {
      throw refuse("The credential public key has no " + name);
    }
    if (!(v instanceof CborBytes b)) {
      throw refuse("The credential public key's " + name + " is not a byte string");
    }
    return b.bytes();
  }

  private static WebauthnException refuse(String message) {
    return new WebauthnException(WebauthnException.Reason.PUBLIC_KEY, message);
  }

  private static WebauthnException refuse(String message, Throwable cause) {
    return new WebauthnException(WebauthnException.Reason.PUBLIC_KEY, message, cause);
  }
}
