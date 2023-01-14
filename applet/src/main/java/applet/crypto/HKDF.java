package applet.crypto;

import javacard.framework.Util;
import javacard.security.CryptoException;

public class HKDF {
    private static byte[] buf;
    private static short bufOffset;

    public static final short REQUIRED_BUFFER_SIZE = 64;

    private static final short PRK_SIZE = HmacSha256.HMAC_SIZE;

    public static final short LENGTH_IS_TOO_LARGE = (short)0x2ea7;

    public static void setBuffer(byte[] b, short offset) {
        buf = b;
        bufOffset = offset;
    }

    public static void startExtract(byte[] salt, short saltOffset, short saltLen) {
        HmacSha256.start(salt, saltOffset, saltLen);
    }

    public static void extractUpdate(byte[] key, short keyOffset, short keyLen) {
        HmacSha256.update(key, keyOffset, keyLen);
    }

    public static void extractFinish() {
        HmacSha256.finalize(buf, bufOffset);
    }

    public static void expand(byte[] info, short infoOffset, short infoLen,
                              byte[] out, short outOffset, short outLen) {

        short afterPRK = (short)(bufOffset + PRK_SIZE);

        byte i = 1;
        while (outLen > 0) {
            // key = PRK
            HmacSha256.start(buf, bufOffset, PRK_SIZE);

            // If not first iteration then feed the previous block
            if (i != 1) {
                HmacSha256.update(out, (short)(outOffset - PRK_SIZE), PRK_SIZE);
            }
            HmacSha256.update(info, infoOffset, infoLen);

            // Feed the index of iteration
            buf[afterPRK] = i;
            HmacSha256.update(buf, afterPRK, (short)1);

            HmacSha256.finalize(buf, afterPRK);

            short toCopy = (outLen < HmacSha256.HMAC_SIZE) ? outLen : HmacSha256.HMAC_SIZE;

            // Copy block to the output buffer
            Util.arrayCopyNonAtomic(
                    buf, afterPRK,
                    out, outOffset,
                    toCopy
            );

            outLen -= toCopy;
            outOffset += toCopy;

            // Original HKDF allows up to 255, but we don't have unsigned byte here.
            // We wouldn't use more than this, but just as debug check
            if (i == 127) {
                CryptoException.throwIt(LENGTH_IS_TOO_LARGE);
            }
            i++;
        }
    }


    public static void clean() {
        Util.arrayFillNonAtomic(buf, bufOffset, REQUIRED_BUFFER_SIZE, (byte)0x17);
        // TODO: zeroize hmacSha256. Right now it gives an exception.
    }
}
