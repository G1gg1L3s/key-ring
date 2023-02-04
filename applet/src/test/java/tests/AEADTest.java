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

    @Test
    void openEmptyDataEmptyAd() throws Exception {
        byte[] plaintext = open(
                "882c64fb5a3be6ac2236f54e03efa3544770217b5da80dc42488da8e2a7c16bc5a76308ba25732369211845820520131",
                "4fbbbd37b749d3ad0ef354f314afbb3b3eb172cf7f25f3b26ad37a2576df39ce",
                "");
        Assert.assertEquals("", new String(plaintext));
    }

    @Test
    void openEmptyDataSmallAd() throws Exception {
        byte[] plaintext = open(
                "4059868e7b7827fff97e792babc22fb80e42b599ab978112904cc8a151b599b230590c466e1ab7c7f383cffbaf253af3",
                "a73fefc24bbbee7a67840bb61388e2b017a552a2386dfcb226f47563bc98421d",
                "small");
        Assert.assertEquals("", new String(plaintext));
    }

    @Test
    void openEmptyDataBigAd() throws Exception {
        byte[] plaintext = open(
                "2fed9cb3f35a9b107b09cd76828d808f521f3d988afc253eef8d02d98f65281e141830838095a0769113b8348746865a",
                "5e33ecc0b4bf858739a318e0c2b1c77338bac07868af7bd60b93098e152ae727",
                "biiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiig");
        Assert.assertEquals("", new String(plaintext));
    }

    @Test
    void openSmallDataEmptyAd() throws Exception {
        byte[] plaintext = open(
                "b560391c8387172440cc334a42c22133d6f5befbaa8c2f6a5663a4f4575ca03f1e8592a329b9b4446a2e1c2c16fa4a5d",
                "cc61434f55323120c5fab294535363d54a4a726150366a98fbc79243163d05c7734095744f",
                "");
        Assert.assertEquals("small", new String(plaintext));
    }

    @Test
    void openSmallDataSmallAd() throws Exception {
        byte[] plaintext = open(
                "f8339111823292b92ef4dfc900e6f0510ac2341f2b87ee2109f684d45826fb139fa157f29eb419a1873b445a70ce57df",
                "9cd878e5826e22d26ff3d8a7fc68f088e3b64455d5fa0ae6eb8a76b03bd46f3ebd11ea895c",
                "small");
        Assert.assertEquals("small", new String(plaintext));
    }

    @Test
    void openSmallDataBigAd() throws Exception {
        byte[] plaintext = open(
                "ce5ae9de490a0a1b4feb23fb03240b07ef062a3751bf27dc5740aabf2ea31fd4d2a50d98223b07d44614bc95a4ab4b6c",
                "2718055c6563c420cf582b64e6cd4ba7cb0e8f3097240428c86c70fb476809a5aa613ccd60",
                "biiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiig");
        Assert.assertEquals("small", new String(plaintext));
    }

    @Test
    void openBigDataEmptyAd() throws Exception {
        byte[] plaintext = open(
                "5ad4a62110f111e5f31596d7b2925c87dd22caa750aca37ba060f1b0bf53773be9dfa455e7e5ac4414c0ed4e4ebab8d3",
                "eaf0a8be916d40af789a68b1dcb15c846ed7bc115ecf7fd5f51959c495ecf6b910237254cfbf7307f5addcbf9ec413c9fefd61f35e443a55917962798f8737f8f25654a1f11a366c021e572362778dda4bf95223a664899b875cdccbfaaf84316ee0db18636fc165",
                "");
        Assert.assertEquals("looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong",
                new String(plaintext));
    }

    @Test
    void openBigDataSmallAd() throws Exception {
        byte[] plaintext = open(
                "6e6eb229600d02b60beb28cbf414afd6053348e7c8aa0f97e9c822901e411b387e5e66cb41d4eadfbef6997ee2b51538",
                "bc4ba9a2a360ef139a96456731daf0d833c832a051a4f83d183d65192dc29fb21ae4fead274e1f222f0d555ab4937c12128b62d20ef95c5316dab9f57688bfd981fb6d91dc05121c6dcd7bdc618a66c9990ff2b49e0002edfe8651b33623b7c8780c69cae0bcdcb6",
                "small");
        Assert.assertEquals("looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong",
                new String(plaintext));
    }

    @Test
    void openBigDataBigAd() throws Exception {
        byte[] plaintext = open(
                "a50db8256a7e8fb65952d96ceacbb62ed963f89fde79b4689ad2a7ac76638beeddcdcff99f2659d6d00504e896165302",
                "5eb2df2480a52a41ce67b57d4fcf6f59999d1425d9dd7657670ecc0dfa664e97c15f754d47040082ac9f3cf34e369a682b54fce366be5868fbb45d5576a72ee589f7f9feed31538f52d5703b630d5d31eff02e923c1bac6b5cff5e3f897029d87199b9fdb2b490f3",
                "biiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiig");
        Assert.assertEquals("looooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong",
                new String(plaintext));
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
        byte[] key = random.generateSeed(48);
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
        byte[] key = random.generateSeed(48);
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
        byte[] key = random.generateSeed(48);
        String keyHex = Utils.toHex(key);

        String ad = "Some data";
        byte[] ct = seal(keyHex, "Something secret", ad);

        ct[ct.length - 20]++;

        ResponseAPDU res = aeadRaw(CryptoApplet.INS_AEAD_OPEN, key, ad.getBytes(), ct);

        Assert.assertEquals(AEAD.AUTHENTICATION_ERROR, res.getSW());
    }
}
