package applet.crypto;

public class Utils {

    public static void xor(
            byte[] src, short srcOffset,
            byte[] dst, short dstOffset,
            short len
    ) {
        for (short i = 0; i < len; i++) {
            dst[(short) (dstOffset + i)] ^= src[(short) (srcOffset + i)];
        }
    }
}
