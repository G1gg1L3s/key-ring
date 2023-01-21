package tests;

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
    protected final AID aid = AIDUtil.create("F000000001");

    public static final int SW_SUCCESS = 0x9000;

    public static boolean simulated = true;

    public CryptoBase() {
        if (simulated) {
            card = new SimulatorCard(aid, CryptoApplet.class);
        } else {
            card = new PhysicalCard();
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
