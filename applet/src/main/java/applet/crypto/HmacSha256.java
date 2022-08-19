package applet.crypto;

import javacard.security.*;

public class HmacSha256 {
    final public static short HMAC_SIZE = 32;

    private static Signature hmac;
    private static HMACKey hmacKey;

    public static void init() {
        hmacKey = (HMACKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
                KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64,
                false // encrypt key
        );
        hmac = Signature.getInstance(
                Signature.ALG_HMAC_SHA_256,
                false // external access
        );
    }

    public static void start(byte[] key, short keyOffset, short keyLength) {
        try {
            hmacKey.setKey(key, keyOffset, keyLength);
            hmac.init(hmacKey, Signature.MODE_SIGN);
        } catch (CryptoException ex) {
            reset();
            throw ex;
        }
    }

    public static void update(byte[] message, short messageOffset, short messageLength) {
        try {
            hmac.update(message, messageOffset, messageLength);
        } catch (CryptoException ex) {
            reset();
            throw ex;
        }
    }

    public static short finalize(byte[] mac, short macOffset) {
        try {
            hmac.sign(
                    null, (short) 0, (short) 0,
                    mac, macOffset);

            return HMAC_SIZE;
        } finally {
            reset();
        }
    }

    public static void reset() {
        hmacKey.clearKey();
    }
}
