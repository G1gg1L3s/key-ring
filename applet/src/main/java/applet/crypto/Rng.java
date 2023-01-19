package applet.crypto;

import javacard.framework.Util;
import javacard.security.RandomData;

public class Rng {
    private static RandomData rng;

    public static void init() {
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    // Fills the buffer with random bytes
    public static void fill(byte[] buff, short offset, short len) {
        rng.generateData(buff, offset, len);
    }
}
