package com.snaphop.webauthn;

import com.snaphop.cbor.CborMap;
import com.snaphop.cbor.CborParseException;
import com.snaphop.cbor.CborReader;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/// Authenticator data (WebAuthn section 6.1), read strictly: the flags must
/// agree with what follows (attested credential data exactly when AT is
/// set, an extensions map exactly when ED is set), and nothing may follow
/// the last part.
final class AuthenticatorData {

  private final byte[] rpIdHash;
  private final int flags;
  private final long signCount;
  private final @Nullable Attested attested;
  private final @Nullable CborMap extensions;

  private AuthenticatorData(byte[] rpIdHash, int flags, long signCount, @Nullable Attested attested, @Nullable CborMap extensions) {
    this.rpIdHash = rpIdHash;
    this.flags = flags;
    this.signCount = signCount;
    this.attested = attested;
    this.extensions = extensions;
  }

  byte[] rpIdHash() {
    return rpIdHash;
  }

  long signCount() {
    return signCount;
  }

  @Nullable Attested attested() {
    return attested;
  }

  @Nullable CborMap extensionsOrNull() {
    return extensions;
  }

  static final int UP = 0x01;
  static final int UV = 0x04;
  static final int BE = 0x08;
  static final int BS = 0x10;
  static final int AT = 0x40;
  static final int ED = 0x80;

  /// The credential a registration made: the authenticator's model (all
  /// zeros when not said), the credential ID, the COSE key exactly as the
  /// authenticator wrote it, and the key read and checked.
  static final class Attested {
    private final UUID aaguid;
    private final byte[] credentialId;
    private final byte[] publicKeyCose;
    private final CoseKey publicKey;

    Attested(UUID aaguid, byte[] credentialId, byte[] publicKeyCose, CoseKey publicKey) {
      this.aaguid = aaguid;
      this.credentialId = credentialId;
      this.publicKeyCose = publicKeyCose;
      this.publicKey = publicKey;
    }

    UUID aaguid() {
      return aaguid;
    }

    byte[] credentialId() {
      return credentialId;
    }

    byte[] publicKeyCose() {
      return publicKeyCose;
    }

    CoseKey publicKey() {
      return publicKey;
    }
  }

  static AuthenticatorData read(byte[] data) {
    if (data.length < 37) {
      throw refuse("The authenticator data is " + data.length + " bytes, shorter than the 37 it must have");
    }
    byte[] rpIdHash = Arrays.copyOfRange(data, 0, 32);
    int flags = data[32] & 0xff;
    long signCount = ByteBuffer.wrap(data, 33, 4).getInt() & 0xffff_ffffL;
    int pos = 37;
    Attested attested = null;
    if ((flags & AT) != 0) {
      if (data.length < pos + 18) {
        throw refuse("The authenticator data ends inside its attested credential data");
      }
      ByteBuffer b = ByteBuffer.wrap(data, pos, 16);
      UUID aaguid = new UUID(b.getLong(), b.getLong());
      pos += 16;
      int idLength = ((data[pos] & 0xff) << 8) | (data[pos + 1] & 0xff);
      pos += 2;
      if (data.length < pos + idLength) {
        throw refuse("The authenticator data's credential ID of " + idLength + " bytes runs past its end");
      }
      byte[] credentialId = Arrays.copyOfRange(data, pos, pos + idLength);
      pos += idLength;
      CborReader.Item key;
      try {
        key = CoseKey.CBOR.readPrefix(data, pos);
      } catch (CborParseException e) {
        throw refuse("The authenticator data's credential public key is not CBOR: " + e.getMessage(), e);
      }
      byte[] cose = Arrays.copyOfRange(data, pos, key.end());
      pos = key.end();
      attested = new Attested(aaguid, credentialId, cose, CoseKey.read(key.value()));
    }
    CborMap extensions = null;
    if ((flags & ED) != 0) {
      if (pos == data.length) {
        throw refuse("The authenticator data's ED flag is set, but it has no extensions");
      }
      CborReader.Item item;
      try {
        item = CoseKey.CBOR.readPrefix(data, pos);
      } catch (CborParseException e) {
        throw refuse("The authenticator data's extensions are not CBOR: " + e.getMessage(), e);
      }
      if (!(item.value() instanceof CborMap map)) {
        throw refuse("The authenticator data's extensions are not a CBOR map");
      }
      extensions = map;
      pos = item.end();
    }
    if (pos != data.length) {
      throw refuse("The authenticator data has " + (data.length - pos) + " bytes after its last part" + ((flags & ED) == 0 ? " (the ED flag is not set)" : ""));
    }
    return new AuthenticatorData(rpIdHash, flags, signCount, attested, extensions);
  }

  boolean has(int flag) {
    return (flags & flag) != 0;
  }

  static WebauthnException refuse(String message) {
    return new WebauthnException(WebauthnException.Reason.AUTHENTICATOR_DATA, message);
  }

  static WebauthnException refuse(String message, Throwable cause) {
    return new WebauthnException(WebauthnException.Reason.AUTHENTICATOR_DATA, message, cause);
  }
}
