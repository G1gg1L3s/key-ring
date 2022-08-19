package crypto;

import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class AesCtr {
    public static final short BLOCK_SIZE = 16;
    public static final short KEY_SIZE = 16;
    public static final short NONCE_SIZE = 16;

    private static final short COUNTER_SIZE = 16;

    private static final short COUNTER_OFFSET = 0;
    private static final short BLOCK_OFFSET = 16;

    // When calling init, the buffer should be at least this length
    public static final short REQUIRED_BUFFER_LENGTH = COUNTER_SIZE + BLOCK_SIZE;

    // Buffer that contains COUNTER and an encrypted BLOCK
    private static byte[] buffer;

    private static AESKey aesKey;
    private static Cipher aes;

    public static void init(byte[] buff) {
        buffer = buff;
        aesKey = (AESKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_AES,
                KeyBuilder.LENGTH_AES_128,
                false // key encryption; if true returns object with javacardx.crypto.KeyEncryption
                      // which is not needed for now
        );
        aes = Cipher.getInstance(
                Cipher.ALG_AES_BLOCK_128_ECB_NOPAD,
                false // externalAccess
        );
    }

    public static void encrypt(
            byte[] key, short keyOffset,
            byte[] nonce, short nonceOffset,
            byte[] data, short dataOffset, short dataLength) {

        try {
            aesKey.setKey(key, keyOffset);
            aes.init(aesKey, Cipher.MODE_ENCRYPT);

            Util.arrayCopyNonAtomic(
                    nonce, nonceOffset, // src
                    buffer, COUNTER_OFFSET, // dest
                    NONCE_SIZE);

            short left = dataLength;
            while (left > 0) {
                aes.update(
                        buffer, COUNTER_OFFSET, NONCE_SIZE, // input
                        buffer, BLOCK_OFFSET // output
                );

                short len = left < BLOCK_SIZE ? left : BLOCK_SIZE;

                Utils.xor(
                        buffer, BLOCK_OFFSET, // src
                        data, dataOffset, // dest
                        len);

                dataOffset += len;
                left -= len;

                incCounter();
            }
        } finally {
            aesKey.clearKey();
            Util.arrayFillNonAtomic(buffer, (short) 0, (short) buffer.length, (byte) 0x00);
        }

    }

    public static void decrypt(
            byte[] key, short keyOffset,
            byte[] nonce, short nonceOffset,
            byte[] data, short dataOffset, short dataLength) {
        // Beauty of stream ciphers :)
        encrypt(key, keyOffset, nonce, nonceOffset, data, dataOffset, dataLength);
    }

    private static void incCounter() {
        for (short i = BLOCK_SIZE - 1; i >= 0; i--) {
            short offset = (short) (COUNTER_OFFSET + i);
            buffer[offset]++;
            // if this digit wrapped around, we go to the next
            if (buffer[offset] != 0x00) {
                break;
            }
        }
    }
}
