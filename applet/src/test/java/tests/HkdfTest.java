package tests;

import applet.crypto.CryptoApplet;
import common.Utils;
import org.junit.Assert;
import org.junit.jupiter.api.Test;


import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class HkdfTest extends CryptoBase {
    byte[] hkdf(byte[] salt, byte[] info, byte[] key, byte outputLength) throws Exception {
        byte[] apduData = new byte[4 + salt.length + info.length + key.length];
        apduData[0] = (byte)salt.length;
        apduData[1] = (byte)info.length;
        apduData[2] = (byte)key.length;
        apduData[3] = outputLength;

        int saltOffset = 4;
        int infoOffset = saltOffset + salt.length;
        int dataOffset = infoOffset + info.length;

        System.arraycopy(salt, 0, apduData, saltOffset, salt.length);
        System.arraycopy(info, 0, apduData, infoOffset, info.length);
        System.arraycopy(key, 0, apduData, dataOffset, key.length);

        CommandAPDU apdu = new CommandAPDU(0x00, CryptoApplet.INS_HKDF_HMAC_SHA256, 0x00, 0x00, apduData);
        System.out.println("apdu length " + apdu.getBytes().length);
        ResponseAPDU response = card.transmit(apdu);
        Assert.assertEquals(Integer.toHexString(response.getSW()), Integer.toHexString(SW_SUCCESS));

        return response.getData();
    }

    String hkdfHex(String salt, String info, String key, int outputLength) throws Exception {
        byte[] r = hkdf(Utils.parseHex(salt), Utils.parseHex(info), Utils.parseHex(key), (byte)outputLength);
        return Utils.toHex(r);
    }

    @Test
    public void simple() throws Exception {
        String received = hkdfHex("69e7c50157db893b46247bbebf6b9a56", "dfc9fa619bc70ffe787af0cdc5b88718", "68656c6c6f", 32);
        Assert.assertEquals("a394da30a4943dbb2d13d832631f7a088afc3faa952425a3c22467bd1890812b", received);
    }

    @Test
    public void emptyInfo() throws Exception {
        String received = hkdfHex("736f6d652073616c74", "", "7275736e692070697a6461", 36);
        Assert.assertEquals("6a10b2c1662ee96e27205ccead14cecb45e9ec0b3228b510690a3068cc26184cf07b689d", received);
    }

    @Test
    public void emptySalt() throws Exception {
        String received = hkdfHex("", "736f6d6520696e666f", "d0b9d0bed0b1d0b0d0bdd0b020d0bad0b0d186d0b0d0bfd0bdd18f", 78);
        Assert.assertEquals("53a2e663ad103af70add5b55edcaaf3501e181f7cd4d6f2c87f18948f6beb408cdbffbe51b716a9f68920e4dfb89b5cc0e776c687665ef6834ed688c58335dd716b4254c5a51cbf6b9cc3ec1cc06", received);
    }

    @Test
    public void emptyInfoAndSalt() throws Exception {
        String received = hkdfHex("", "", "d185d0b0d0b920d0bad180d0b8d0bcd181d18cd0bad0b8d0b920d0bcd196d181d18220d0b7d0b0d186d0b2d196d182d0b520d0b1d0b0d0b2d0bed0b2d0bdd0bed18e", 8);
        Assert.assertEquals("3c9b18d0f9bdbacf", received);
    }

    @Test
    public void bigInfoSaltAndOutput() throws Exception {
        String received = hkdfHex("d0b2d0b5d0b5d0b5d0b5d0b5d0bbd0b8d0b8d0b8d0b8d0b8d0b8d0b8d0b8d0bad0b0d0b020d181d196d196d196d196d196d196d196d196d196d196d0bbd18c", "d0b2d0b5d0b5d0b5d0b5d0bbd0b8d0b8d0bad0b5d0b5d0b5d0b520696e666f6f6f6f", "d194d0b1d183d187d19620d0bcd0bed181d0bad0b0d0bbd196", 127);
        Assert.assertEquals("6eeeabef8c227c803747d18d3e3f32bd5a6fc0906f586844fe325a58ba48a671c66056b0086fb0749f5de1e38eac426e21140a14c8162cb6e51f7c62dc75905ae84367c17909f22ed561057c61ffcab1ee62860f44d47de64bca807c9714c9f458643047901da2997c38adac7aa8857a7b7d6915ced0816600ad8d44dc6007", received);
    }
}
