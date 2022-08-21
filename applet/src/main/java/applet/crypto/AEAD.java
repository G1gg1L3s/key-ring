package applet.crypto;

import javacard.framework.Util;
import javacard.security.CryptoException;

// Authenticated encryption with associated data;
// The Underlying algorithm is aes-128-ctr-hmac-256-128
// Which means that the cipher is aes-128-ctr
// and the tag is computed as:
// ```
// digest = hmac-sha256(hmac_key, associated_data || encrypted_payload || nonce || length(associated_data).to_u64())
// tag = truncate(digest, 16 bytes)
// ```
// The resulting ciphertext has the following format:
// ```
// [encrypted payload] [16-byte nonce] [16-byte tag]
// ```
//
// The key is 48 bytes. First 16 bytes are used for AES, and the last
// 32 are used for the tag.
//
public class AEAD {
    public static final short NONCE_SIZE = AesCtr.NONCE_SIZE;
    // We truncate output of the hmac
    public static final short TAG_SIZE = 16;
    public static final short ADDITIONAL_DATA_SIZE = NONCE_SIZE + TAG_SIZE;
    public static final short KEY_SIZE = AesCtr.KEY_SIZE + HmacSha256.HMAC_SIZE;

    public static final short AUTHENTICATION_ERROR = (short) 0x2d58;
    public static final short CIPHERTEXT_TOO_SMALL = (short) 0xc849;

    private static final short U64_SIZE = 8;
    private static final short U64_OFFSET = 0;
    private static final short HMAC_OUTPUT_OFFSET = U64_SIZE;

    // [length of associated data in big endian format] + [hmac]
    public static short REQUIRED_BUFFER_SIZE = U64_SIZE + HmacSha256.HMAC_SIZE;

    private static byte[] buffer;

    public static void init(byte[] buff) {
        buffer = buff;
    }

    public static short geRequiredBufferLength(short plaintext) {
        return (short) (plaintext + ADDITIONAL_DATA_SIZE);
    }

    public static short calculateTag(
            byte[] key, short keyOffset, short keyLen,
            byte[] ad, short adOffset, short adLen,
            byte[] ciphertext, short ciphertextOffset, short ciphertextLen,
            byte[] tag, short tagOffset) {
        // Serialize associated data length as u64
        Util.arrayFillNonAtomic(buffer, U64_OFFSET, U64_SIZE, (byte) 0x00);
        Util.setShort(
                buffer,
                (short) (U64_OFFSET + 6), // length is 2 byte, so we set the last two bytes of the
                                          // length buffer
                adLen);

        HmacSha256.start(key, keyOffset, keyLen);
        HmacSha256.update(ad, adOffset, adLen);
        HmacSha256.update(ciphertext, ciphertextOffset, ciphertextLen);
        HmacSha256.update(buffer, (short) 0, U64_SIZE);
        HmacSha256.finalize(buffer, HMAC_OUTPUT_OFFSET);

        Util.arrayCopyNonAtomic(
                buffer, HMAC_OUTPUT_OFFSET, // src
                tag, tagOffset, // dest
                TAG_SIZE);
        return TAG_SIZE;
    }

    public static short seal(
            byte[] key, short keyOffset,
            byte[] plaintext, short plainOffset, short plainLen,
            byte[] ad, short adOffset, short adLen) {
        // 1. Generate nonce. Place it after the ciphertext
        short nonceOffset = (short) (plainOffset + plainLen);
        Rng.fill(plaintext, nonceOffset, NONCE_SIZE);

        // 2. Split keys
        short encKeyOffset = keyOffset;
        short tagKeyOffset = (short) (keyOffset + AesCtr.KEY_SIZE);

        // 3. Encrypt
        AesCtr.encrypt(
                key, encKeyOffset,
                plaintext, nonceOffset,
                plaintext, plainOffset, plainLen);

        // We also want to protect the nonce
        short ciphertextLen = (short) (plainLen + NONCE_SIZE);

        // 4. Derive tag
        short tagOffset = (short) (nonceOffset + NONCE_SIZE);
        calculateTag(
                key, tagKeyOffset, HmacSha256.HMAC_SIZE, // tag key
                ad, adOffset, adLen, // associated data
                plaintext, plainOffset, ciphertextLen, // ciphertext
                plaintext, tagOffset // place tag after the ciphertext
        );

        return (short) (plainLen + ADDITIONAL_DATA_SIZE);
    }

    public static short open(
            byte[] key, short keyOffset,
            byte[] ciphertext, short cipherOffset, short cipherLen,
            byte[] ad, short adOffset, short adLen) {
        if (cipherLen < ADDITIONAL_DATA_SIZE) {
            CryptoException.throwIt(CIPHERTEXT_TOO_SMALL);
        }
        // payloadLen is length of the actual data
        short payloadLen = (short) (cipherLen - ADDITIONAL_DATA_SIZE);
        short nonceOffset = (short) (cipherOffset + payloadLen);
        short tagOffset = (short) (nonceOffset + TAG_SIZE);

        // Split key
        short encKeyOffset = keyOffset;
        short tagKeyOffset = (short) (keyOffset + AesCtr.KEY_SIZE);

        // Derive tag
        calculateTag(
                key, tagKeyOffset, HmacSha256.HMAC_SIZE, // tag key
                ad, adOffset, adLen, // associated data
                ciphertext, cipherOffset, (short) (payloadLen + NONCE_SIZE), // ciphertext
                buffer, HMAC_OUTPUT_OFFSET // place tag in the buffer
        );

        boolean eq = Utils.const_eq(buffer, HMAC_OUTPUT_OFFSET, ciphertext, tagOffset, TAG_SIZE);
        if (!eq) {
            CryptoException.throwIt(AUTHENTICATION_ERROR);
        }

        AesCtr.decrypt(
                key, encKeyOffset,
                ciphertext, nonceOffset,
                ciphertext, cipherOffset, payloadLen);

        return payloadLen;
    }
}
