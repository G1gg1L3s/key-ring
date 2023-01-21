package tests;

import applet.crypto.CryptoApplet;
import javacard.framework.AID;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.HashSet;
import java.util.Set;

public class RngTest extends CryptoBase {
    byte[] rand(short len) throws Exception {
        byte[] apduData = new byte[2];
        putShort((short) len, apduData, 0);
        CommandAPDU apdu = new CommandAPDU(0x00, CryptoApplet.INS_RAND, 0x00, 0x00, apduData);
        ResponseAPDU response = card.transmit(apdu);
        return response.getData();
    }

    @Test
    public void checkLength() throws Exception {
        for (short i = 0; i < 128; i++) {
            byte[] random = rand(i);
            Assert.assertEquals(i, random.length);
        }
    }

    @Test
    public void dontRepeatAfterDeselect() throws Exception {
        Set<byte[]> set = new HashSet<>();

        int numberOfRequests = 128;

        card.disconnect();
        card.connect();

        for (int i = 0; i < numberOfRequests; i++) {
            set.add(rand((short) 32));
        }

        card.disconnect();
        card.connect();

        for (int i = 0; i < numberOfRequests; i++) {
            set.add(rand((short) 32));
        }
        Assert.assertEquals(set.size(), numberOfRequests * 2);
    }

    @Test
    public void dontRepeatAfterReseed() throws Exception {
        Set<byte[]> set = new HashSet<>();

        int numberOfRequests = 1024;

        card.disconnect();
        card.connect();
        for (int i = 0; i < numberOfRequests; i++) {
            set.add(rand((short) 32));
        }

        Assert.assertEquals(set.size(), numberOfRequests);
    }
}
