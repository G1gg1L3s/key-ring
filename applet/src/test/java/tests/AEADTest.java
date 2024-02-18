package tests;

import applet.crypto.AEAD;
import applet.crypto.CryptoApplet;
import common.Utils;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.SecureRandom;

public class AEADTest extends CryptoBase {
    ResponseAPDU aeadRaw(short ins, byte[] key, byte[] ad, byte[] data) throws Exception {
        int keyOffset = 0;
        int adLenOffset = key.length;
        int adOffset = adLenOffset + 2;
        int dataLenOffset = adOffset + ad.length;
        int dataOffset = dataLenOffset + 2;

        byte[] apduData = new byte[key.length + 2 + ad.length + 2 + data.length];
        // resulting array is...
        // 16-byte key
        System.arraycopy(key, 0, apduData, keyOffset, key.length);
        // then 2 byte length of associated data
        putShort((short) ad.length, apduData, adLenOffset);
        // then associated data itself
        System.arraycopy(ad, 0, apduData, adOffset, ad.length);
        // then 2-byte data length
        putShort((short) data.length, apduData, dataLenOffset);
        // then data itself
        System.arraycopy(data, 0, apduData, dataOffset, data.length);

        CommandAPDU apdu = new CommandAPDU(0x00, ins, 0x00, 0x00, apduData);
        ResponseAPDU response = card.transmit(apdu);
        return response;
    }

    byte[] aead(short ins, byte[] key, byte[] ad, byte[] data) throws Exception {
        ResponseAPDU res = aeadRaw(ins, key, ad, data);
        Assert.assertEquals(SW_SUCCESS, res.getSW());
        return res.getData();
    }

    byte[] open(String keyHex, String hexCt, String ad) throws Exception {
        byte[] key = Utils.parseHex(keyHex);
        byte[] data = Utils.parseHex(hexCt);

        return aead(CryptoApplet.INS_AEAD_OPEN, key, ad.getBytes(), data);
    }

    byte[] seal(String keyHex, String plaintext, String ad) throws Exception {
        byte[] key = Utils.parseHex(keyHex);
        return aead(CryptoApplet.INS_AEAD_SEAL, key, ad.getBytes(), plaintext.getBytes());
    }

    void assertOpens(String keyHex, String ciphertextHex, String ad, String expected) throws Exception {
        byte[] plaintext = open(keyHex, ciphertextHex, ad);
        Assert.assertEquals(expected, new String(plaintext));
    }

    @Test
    void openLargeCiphertextLargeAd() throws Exception {
        assertOpens("d46d937c9c0d55c2aef99f4253d83819",
                "fa9deef63c319d366b51e02a4d8c803ea77926d1524203346573511fd3c003b682688ebf6c441c09b06ac7ecd1e57513a0c12bd2be3b7fb779b291dccac8ce1affab5a185429f51218f144d8d1550725cd75b0582e6060e05a19d946a5",
                "a very long string with a length definitely more than a block",
                "a very long string with a length definitely more than a block");
    }

    void encryptDecrypt(String text, String ad) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] key = random.generateSeed(16);
        String keyHex = Utils.toHex(key);

        byte[] ct = seal(keyHex, text, ad);
        byte[] pt = open(keyHex, Utils.toHex(ct), ad);

        Assert.assertEquals(text, new String(pt));
    }

    @Test
    void encryptDecryptEmptyPlaintextEmptyAD() throws Exception {
        encryptDecrypt("", "");
    }

    @Test
    void encryptDecryptEmptyPlaintextSmallAD() throws Exception {
        encryptDecrypt("", "small");
    }

    @Test
    void encryptDecryptEmptyPlaintextBigAD() throws Exception {
        encryptDecrypt("", "biiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiig");
    }

    @Test
    void encryptDecryptSmallPlaintextEmptyAD() throws Exception {
        encryptDecrypt("small", "");
    }

    @Test
    void encryptDecryptSmallPlaintextSmallAD() throws Exception {
        encryptDecrypt("small", "smallish");
    }

    @Test
    void encryptDecryptSmallPlaintextBigAD() throws Exception {
        encryptDecrypt("small", "biiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiig");
    }

    @Test
    void encryptDecryptBigPlaintextEmptyAD() throws Exception {
        encryptDecrypt("BIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIG", "");
    }

    @Test
    void encryptDecryptBigPlaintextSmallAD() throws Exception {
        encryptDecrypt("BIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIG", "small");
    }

    @Test
    void encryptDecryptBigPlaintextBigAD() throws Exception {
        encryptDecrypt("BIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIG", "huuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuge");
    }

    @Test
    void encryptFlipByteDecrypt() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] key = random.generateSeed(16);
        String keyHex = Utils.toHex(key);

        String ad = "Some data";
        byte[] ct = seal(keyHex, "Something secret", ad);

        ct[1]++;

        ResponseAPDU res = aeadRaw(CryptoApplet.INS_AEAD_OPEN, key, ad.getBytes(), ct);

        Assert.assertEquals(AEAD.AUTHENTICATION_ERROR, res.getSW());
    }

    @Test
    void encryptFlipTagDecrypt() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] key = random.generateSeed(16);
        String keyHex = Utils.toHex(key);

        String ad = "Some data";
        byte[] ct = seal(keyHex, "Something secret", ad);

        ct[ct.length - 1]++;

        ResponseAPDU res = aeadRaw(CryptoApplet.INS_AEAD_OPEN, key, ad.getBytes(), ct);

        Assert.assertEquals(AEAD.AUTHENTICATION_ERROR, res.getSW());
    }

    @Test
    void encryptFlipNonceDecrypt() throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] key = random.generateSeed(16);
        String keyHex = Utils.toHex(key);

        String ad = "Some data";
        byte[] ct = seal(keyHex, "Something secret", ad);

        ct[ct.length - 20]++;

        ResponseAPDU res = aeadRaw(CryptoApplet.INS_AEAD_OPEN, key, ad.getBytes(), ct);

        Assert.assertEquals(AEAD.AUTHENTICATION_ERROR, res.getSW());
    }
}
