package tests;

import applet.crypto.CryptoApplet;
import common.Utils;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class HmacSha256Test extends CryptoBase {
    void testWith(byte[] key, byte[] data, String expected) throws Exception {
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
        ResponseAPDU response = card.transmit(apdu);
        byte[] raw = response.getData();

        Assert.assertEquals(expected, Utils.toHex(raw));
    }

    @Test
    public void simple() throws Exception {
        testWith("key".getBytes(), "input".getBytes(),
                "9e089ec13af881a8ac227a736c3e7c490ea3b4afca0c5f83dff6393b683a72e3");
    }

    @Test
    public void emptyKey() throws Exception {
        testWith("".getBytes(), "input".getBytes(), "d00c6678e09a0503bdbf68009b6af1c0593fe6a5318609540fef362e7c410219");
    }

    @Test
    public void emptyInput() throws Exception {
        testWith("key".getBytes(), "".getBytes(), "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0");
    }

    @Test
    public void emptyEverything() throws Exception {
        testWith("".getBytes(), "".getBytes(), "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
    }

    @Test
    public void bigInput() throws Exception {
        String input = "glory to Ukraine!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
        testWith("key".getBytes(), input.getBytes(),
                "97e1db8880a996504eaf58f7fc6c097b26341ce8b1397b3d8b2fe1e48b64be58");
    }

    @Test
    public void bigKey() throws Exception {
        String key = "fuck russians|fuck russians|fuck russians|fuck russians|fuck ru."; // 64 bytes, block size
        testWith(key.getBytes(), "input".getBytes(),
                "485ea83cf99992e5655e1860d2115c347d131dcc8c897b519aabf419f7fdf2c5");
    }
}
