package applet.crypto;

import javacard.framework.*;

public class CryptoApplet extends Applet {
    final public static byte INS_HMAC_SHA256 = 0x25;
    final public static byte INS_AES_CTR_ENC = 0x26;
    final public static byte INS_AES_CTR_DEC = 0x27;
    final public static byte INS_RAND = 0x28;
    public static byte[] buffer;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptoApplet().register();
        HmacSha256.init();
        AesCtr.init(JCSystem.makeTransientByteArray(AesCtr.REQUIRED_BUFFER_LENGTH, JCSystem.CLEAR_ON_DESELECT));
        Rng.init(
                new byte[Rng.SEED_SIZE],
                JCSystem.makeTransientByteArray(Rng.REQUIRED_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT)
        );
        buffer = JCSystem.makeTransientByteArray((short) 1024, JCSystem.CLEAR_ON_DESELECT);
    }

    public CryptoApplet() {

    }

    @Override
    public boolean select() {
        Rng.reseed();
        return true;
    }

    public void hmacSha256(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        // we expect a buffer with the following format:
        //
        // [2-byte key length] [key] [2-byte data length] [data]
        //
        short keyLength = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        short keyOffset = (short) (ISO7816.OFFSET_CDATA + 2);
        short dataLength = Util.getShort(buffer, (short) (keyOffset + keyLength));
        short dataOffset = (short) (keyOffset + keyLength + 2);

        HmacSha256.start(buffer, keyOffset, keyLength);
        HmacSha256.update(buffer, dataOffset, dataLength);
        short outLen = HmacSha256.finalize(buffer, ISO7816.OFFSET_CDATA);

        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, outLen);
    }

    public void aes_ctr(APDU apdu, boolean encrypt) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        // we expect a buffer with the following format:
        //
        // [16-byte key] [16-byte nonce] [2-byte data length] [data]
        //

        short keyOffset = ISO7816.OFFSET_CDATA;
        short nonceOffset = ISO7816.OFFSET_CDATA + 16;
        short lengthOffset = ISO7816.OFFSET_CDATA + 32;
        short dataOffset = ISO7816.OFFSET_CDATA + 34;
        short dataLength = Util.getShort(buffer, lengthOffset);

        if (encrypt) {
            AesCtr.encrypt(
                    buffer, keyOffset,
                    buffer, nonceOffset,
                    buffer, dataOffset, dataLength);
        } else {
            AesCtr.decrypt(
                    buffer, keyOffset,
                    buffer, nonceOffset,
                    buffer, dataOffset, dataLength);
        }

        apdu.setOutgoingAndSend(dataOffset, dataLength);
    }

    public void rand(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        // we expect only 2-byte length, which specifies number of bytes
        // to return
        short len = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        Rng.fill(buffer, ISO7816.OFFSET_CDATA, len);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_HMAC_SHA256:
                hmacSha256(apdu);
                break;
            case INS_AES_CTR_ENC:
            case INS_AES_CTR_DEC:
                boolean encrypt = buffer[ISO7816.OFFSET_INS] == INS_AES_CTR_ENC;
                aes_ctr(apdu, encrypt);
                break;
            case INS_RAND:
                rand(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
    }
}
