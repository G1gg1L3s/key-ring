package applet.crypto;

public class Utils {

    public static boolean const_eq(byte[] a, short offsetA, byte[] b, short offsetB, short length) {
        byte result = 0;
        for (byte i = 0; i < length; i++) {
            result |= (byte) (a[(short) (offsetA + i)] ^ b[(short) (offsetB + i)]);
        }
        return result == 0;
    }

    public static void xor(
            byte[] src, short srcOffset,
            byte[] dst, short dstOffset,
            short len) {
        for (short i = 0; i < len; i++) {
            dst[(short) (dstOffset + i)] ^= src[(short) (srcOffset + i)];
        }
    }
}
