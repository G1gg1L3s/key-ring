package tests;

import crypto.AesCtr;
import crypto.CryptoApplet;
import crypto.Utils;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class AesCtrTest extends CryptoBase {
    void testEncrypt(String keyHex, String nonceHex, String dataHex, String expectedHex) {
        testIns(CryptoApplet.INS_AES_CTR_ENC, keyHex, nonceHex, dataHex, expectedHex);
    }

    void testDecrypt(String keyHex, String nonceHex, String dataHex, String expectedHex) {
        testIns(CryptoApplet.INS_AES_CTR_DEC, keyHex, nonceHex, dataHex, expectedHex);
    }

    void testIns(byte ins, String keyHex, String nonceHex, String dataHex, String expectedHex) {
        byte[] key = Utils.parseHex(keyHex);
        byte[] nonce = Utils.parseHex(nonceHex);
        byte[] data = Utils.parseHex(dataHex);

        byte[] apduData = new byte[16 + 16 + 2 + data.length];
        // resulting array is...
        // 16 byte key
        System.arraycopy(key, 0, apduData, 0, key.length);
        // then 16 byte nonce
        System.arraycopy(nonce, 0, apduData, 16, nonce.length);
        // then 2 byte data length
        putShort((short) data.length, apduData, 32);
        // then data itself
        System.arraycopy(data, 0, apduData, 34, data.length);

        CommandAPDU apdu = new CommandAPDU(0x00, ins, 0x00, 0x00, apduData);
        ResponseAPDU response = card.transmitCommand(apdu);
        byte[] raw = response.getData();

        Assert.assertEquals(expectedHex, Utils.toHex(raw));
    }

    @Test
    public void simple() {
        testEncrypt(
                "00112233445566778899aabbccddeeff",
                "ffeeddccbbaa99887766554433221100",
                "476c6f727920746f20556b7261696e65210a",
                "354d564b618239122eb699505a9335504ca9");

        testDecrypt(
                "00112233445566778899aabbccddeeff",
                "ffeeddccbbaa99887766554433221100",
                "354d564b618239122eb699505a9335504ca9",
                "476c6f727920746f20556b7261696e65210a");
    }

    @Test
    public void empty() {
        testEncrypt(
                "00112233445566778899aabbccddeeff",
                "ffeeddccbbaa99887766554433221100",
                "",
                "");

        testDecrypt(
                "00112233445566778899aabbccddeeff",
                "ffeeddccbbaa99887766554433221100",
                "",
                "");
    }

    @Test
    public void oneByte() {
        testEncrypt(
                "00112233445566778899aabbccddeeff",
                "ffeeddccbbaa99887766554433221100",
                "aa",
                "d8");

        testDecrypt(
                "00112233445566778899aabbccddeeff",
                "ffeeddccbbaa99887766554433221100",
                "d8",
                "aa");
    }

    @Test
    public void oneLessThanBlockSize() {
        testEncrypt(
                "00112233445566778899aabbccddeeff",
                "ffeeddccbbaa99887766554433221100",
                "0000000000000000000000000000000000112233445566778899aabbccddee",
                "7221393918a24d7d0ee3f2223bfa5b356db21574de4ee80ea5f2e114854a12");

        testDecrypt(
                "00112233445566778899aabbccddeeff",
                "ffeeddccbbaa99887766554433221100",
                "7221393918a24d7d0ee3f2223bfa5b356db21574de4ee80ea5f2e114854a12",
                "0000000000000000000000000000000000112233445566778899aabbccddee");
    }

    @Test
    public void overflowCounter() {
        testEncrypt(
                "00112233445566778899aabbccddeeff",
                "fffffffffffffffffffffffffffffffa",
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "3f88c57058b06d24966ecc85fdc1ba988dee29c71512296935a25be9e5fcc746b9532210373c6dcb1e892b634241854ad1eb");

        testDecrypt(
                "00112233445566778899aabbccddeeff",
                "fffffffffffffffffffffffffffffffa",
                "3f88c57058b06d24966ecc85fdc1ba988dee29c71512296935a25be9e5fcc746b9532210373c6dcb1e892b634241854ad1eb",
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    }
}
