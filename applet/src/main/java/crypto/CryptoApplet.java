package crypto;

import javacard.framework.*;

public class CryptoApplet extends Applet {
    final public static byte INS_HMAC_SHA256 = 0x25;
    public static byte[] hash_buff;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptoApplet().register();
        HmacSha256.init(JCSystem.makeTransientByteArray(HmacSha256.REQUIRED_BUFFER_LENGTH, JCSystem.CLEAR_ON_DESELECT));
        hash_buff = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
    }

    public CryptoApplet() {

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

        short outLengh = HmacSha256.compute(
                // key
                buffer,
                keyOffset,
                keyLength,

                // message
                buffer,
                dataOffset,
                dataLength,

                // mac
                buffer,
                ISO7816.OFFSET_CDATA);

        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, outLengh);
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_HMAC_SHA256:
                hmacSha256(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
    }
}
