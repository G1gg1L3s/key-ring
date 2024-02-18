package tests;

import common.Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

import com.licel.jcardsim.utils.AIDUtil;

import applet.crypto.CryptoApplet;
import javacard.framework.AID;
import tests.jcard.Card;
import tests.jcard.PhysicalCard;
import tests.jcard.SimulatorCard;

import java.security.Security;

public class CryptoBase {
    protected Card card;
    protected final AID simulatedAid = AIDUtil.create("F000000001");
    protected final String realAid = "01FFFF0405060708090102";

    public static final int SW_SUCCESS = 0x9000;

    public static boolean simulated = System.getProperty("device") == null;

    public CryptoBase() {
        if (simulated) {
            card = new SimulatorCard(simulatedAid, CryptoApplet.class);
        } else {
            byte[] aid = Utils.parseHex(realAid);
            card = new PhysicalCard(aid);
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    void putShort(short a, byte[] arr, int offset) {
        arr[offset] = (byte) ((a & 0xFF00) >> 8);
        arr[offset + 1] = (byte) (a & 0x00FF);
    }

    @BeforeAll
    public static void setUpClass() throws Exception {
    }

    @AfterAll
    public static void tearDownClass() throws Exception {
    }

    @BeforeEach
    public void setUpMethod() throws Exception {
        card.connect();
    }

    @AfterEach
    public void tearDownMethod() throws Exception {
        card.disconnect();
    }
}
