package tests;

import applet.crypto.CryptoApplet;
import common.Utils;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class HmacSha256Test extends CryptoBase {
    void testWith(byte[] key, byte[] data, String expected) {
        byte[] apduData = new byte[2 + key.length + 2 + data.length];
        // resulting array is...
        // 2 byte key length
        putShort((short) key.length, apduData, 0);
        // then the key
        System.arraycopy(key, 0, apduData, 2, key.length);
        // then 2 byte data length
        putShort((short) data.length, apduData, 2 + key.length);
        // then data itself
        System.arraycopy(data, 0, apduData, 2 + key.length + 2, data.length);

        CommandAPDU apdu = new CommandAPDU(0x00, CryptoApplet.INS_HMAC_SHA256, 0x00, 0x00, apduData);
        ResponseAPDU response = card.transmitCommand(apdu);
        byte[] raw = response.getData();

        Assert.assertEquals(expected, Utils.toHex(raw));
    }

    @Test
    public void simple() {
        testWith("key".getBytes(), "input".getBytes(),
                "9e089ec13af881a8ac227a736c3e7c490ea3b4afca0c5f83dff6393b683a72e3");
    }

    @Test
    public void emptyInput() {
        testWith("key".getBytes(), "".getBytes(), "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0");
    }

    @Test
    public void bigInput() {
        String input = "glory to ukraine".repeat(8);
        testWith("key".getBytes(), input.getBytes(),
                "958eff03668143bbb558f97f731d008abafa297b245ec7bedacf6260018a2e61");
    }

    @Test
    public void bigKey() {
        String key = "glory to ukraine".repeat(4); // 64 bytes, block size
        testWith(key.getBytes(), "input".getBytes(),
                "4fbaee54a85de8c6187ff1554a7bb56383d64afd8719bc1e43691dffaefe8bd4");
    }
}
