package applet.crypto;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;

public class HmacSha256 {

    public static final short BLOCK_SIZE = 64;
    public static final short HASH_SIZE = 32;
    public static final short HMAC_SIZE = HASH_SIZE;

    // When calling init, the buffer should be at least this length
    public static final short REQUIRED_BUFFER_LENGTH = BLOCK_SIZE + HASH_SIZE;

    // TODO: extract somewhere else
    public static final short SW_HMAC_UNSUPPORTED_KEY_LENGTH = (short) 0x9c1E;

    private static byte[] buffer;
    private static MessageDigest sha256;

    public static void init(byte[] tmp) {
        sha256 = MessageDigest.getInstance(
                MessageDigest.ALG_SHA_256,
                false // externalAccess
        );
        buffer = tmp;
    }

    public static void start(byte[] key, short keyOffset, short keyLength) {
        try {
            // Sorry, we don't support big keys :c
            if (keyLength > BLOCK_SIZE || keyLength < 0) {
                ISOException.throwIt(SW_HMAC_UNSUPPORTED_KEY_LENGTH);
            }

            // Copy the key into the beginning of the buffer and xor producing the inner key
            for (short i = 0; i < keyLength; i++) {
                short k = (short) (keyOffset + i);
                buffer[i] = (byte) (key[k] ^ 0x36);
            }

            // padd inner key to the block size
            Util.arrayFillNonAtomic(
                    buffer,
                    keyLength, // offset, after the key
                    (short) (BLOCK_SIZE - keyLength), // length, to the end of the BLOCK
                    (byte) 0x36);

            sha256.reset();
            // write inner key
            sha256.update(buffer, (short) 0, BLOCK_SIZE);
        } catch (CryptoException ex) {
            clean();
            throw ex;
        }
    }

    public static void update(byte[] message, short messageOffset, short messageLength) {
        try {
            sha256.update(message, messageOffset, messageLength);
        } catch (CryptoException ex) {
            clean();
            throw ex;
        }
    }

    public static short finalize(byte[] mac, short macOffset) {
        try {
            // write hash after the key in buffer
            sha256.doFinal(
                    // src
                    buffer, (short)0, (short)0,
                    buffer, // output
                    BLOCK_SIZE // output offset; the hash will be after the inner key
            );

            // compute outer key
            for (short i = 0; i < BLOCK_SIZE; i++) {
                // (key xor 0x36) xor 0x36 xor 0x5c = key xor 0x5c
                buffer[i] ^= 0x36 ^ 0x5c;
            }

            sha256.reset();
            // compute hash from the `outer key || hash`
            sha256.doFinal(buffer, (short) 0, (short) (BLOCK_SIZE + HASH_SIZE), mac, macOffset);

            return HASH_SIZE;
        } finally {
            clean();
        }
    }

    public static void clean() {
        sha256.reset();
        // Zeroize the buffer
        Util.arrayFillNonAtomic(
                buffer, (short) 0, (short) buffer.length,
                (byte) 0x00 // byte to fill with
        );
    }
}
