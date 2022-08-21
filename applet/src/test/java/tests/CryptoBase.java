package tests;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import applet.crypto.CryptoApplet;
import javacard.framework.AID;

public class CryptoBase {
    protected CardSimulator card;
    protected final AID aid = AIDUtil.create("F000000001");

    public static final int SW_SUCCESS = 0x9000;

    public CryptoBase() {
        card = new CardSimulator();
        card.installApplet(aid, CryptoApplet.class);
        card.selectApplet(aid);
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

    }

    @AfterEach
    public void tearDownMethod() throws Exception {
    }
}
