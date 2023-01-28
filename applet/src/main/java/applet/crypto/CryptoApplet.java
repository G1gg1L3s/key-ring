package applet.crypto;

import javacard.framework.*;

public class CryptoApplet extends Applet {
    final public static byte INS_HMAC_SHA256 = 0x25;
    final public static byte INS_AES_CTR_ENC = 0x26;
    final public static byte INS_AES_CTR_DEC = 0x27;
    final public static byte INS_RAND = 0x28;
    final public static byte INS_AEAD_SEAL = 0x29;
    final public static byte INS_AEAD_OPEN = 0x30;
    final public static byte INS_HKDF_HMAC_SHA256 = 0x3a;
    final public static byte INS_P256_GENERATE_NEW_KEYPAIR = 0x41;
    final public static byte INS_P256_ECDH = 0x42;
    public static byte[] buffer;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptoApplet().register();
        HmacSha256.init(JCSystem.makeTransientByteArray(HmacSha256.REQUIRED_BUFFER_LENGTH, JCSystem.CLEAR_ON_DESELECT));
        AesCtr.init(JCSystem.makeTransientByteArray(AesCtr.REQUIRED_BUFFER_LENGTH, JCSystem.CLEAR_ON_DESELECT));
        Rng.init();
        AEAD.init(JCSystem.makeTransientByteArray(AEAD.REQUIRED_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT));
        buffer = JCSystem.makeTransientByteArray((short) 1024, JCSystem.CLEAR_ON_DESELECT);
        P256.init();
        HKDF.setBuffer(JCSystem.makeTransientByteArray(HKDF.REQUIRED_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT), (short)0);
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

        HmacSha256.start(buffer, keyOffset, keyLength);
        HmacSha256.update(buffer, dataOffset, dataLength);
        short outLen = HmacSha256.finalize(buffer, ISO7816.OFFSET_CDATA);

        HmacSha256.reset();
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

    public void aead(APDU apdu, boolean seal) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        // we expect the following format:
        //
        // [48-byte key] [2-byte ad length] [ad] [2-byte data length] [data]
        //
        short keyOffset = ISO7816.OFFSET_CDATA;
        short adLenOffset = (short) (keyOffset + AEAD.KEY_SIZE);
        short adLen = Util.getShort(buffer, adLenOffset);
        short adOffset = (short) (adLenOffset + 2);
        short dataLenOffset = (short) (adOffset + adLen);
        short dataLen = Util.getShort(buffer, dataLenOffset);
        short dataOffset = (short) (dataLenOffset + 2);

        short len = 0;

        if (seal) {
            len = AEAD.seal(
                    buffer, keyOffset, // key
                    buffer, dataOffset, dataLen, // plaintext
                    buffer, adOffset, adLen // associated data
            );
        } else {
            len = AEAD.open(
                    buffer, keyOffset, // key
                    buffer, dataOffset, dataLen, // ciphertext
                    buffer, adOffset, adLen // associated data
            );
        }

        apdu.setOutgoingAndSend(dataOffset, len);
    }

    private void hkdf(APDU apdu) {
        apdu.setIncomingAndReceive();

        byte[] buffer = apdu.getBuffer();
        short cdata = apdu.getOffsetCdata();
        // All lengths are 1 byte
        // [salt len] [info len] [key len] [output len] [salt] [info] [...key]
        short saltLen = buffer[cdata];
        short infoLen = buffer[(short)(cdata + 1)];
        short keyLen = buffer[(short)(cdata + 2)];
        short outputLen = buffer[(short)(cdata + 3)];

        short saltOffset = (short)(cdata + 4);
        short infoOffset = (short)(saltOffset + saltLen);
        short keyOffset = (short)(infoOffset + infoLen);

        HKDF.startExtract(buffer, saltOffset, saltLen);
        HKDF.extractUpdate(buffer, keyOffset, keyLen);
        HKDF.extractFinish();

        // Place the result after info at `keyOffset`
        // Because info cannot be overwritten as it is used in every iteration
        HKDF.expand(buffer, infoOffset, infoLen, buffer, keyOffset, outputLen);

        HKDF.clean();
        apdu.setOutgoingAndSend(keyOffset, outputLen);
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_HMAC_SHA256:
                hmacSha256(apdu);
                break;
            case INS_AES_CTR_ENC:
            case INS_AES_CTR_DEC: {
                boolean encrypt = buffer[ISO7816.OFFSET_INS] == INS_AES_CTR_ENC;
                aes_ctr(apdu, encrypt);
                break;
            }
            case INS_RAND:
                rand(apdu);
                break;
            case INS_AEAD_SEAL:
            case INS_AEAD_OPEN: {
                boolean seal = buffer[ISO7816.OFFSET_INS] == INS_AEAD_SEAL;
                aead(apdu, seal);
                break;
            }
            case INS_HKDF_HMAC_SHA256:
                hkdf(apdu);
                break;
            case INS_P256_GENERATE_NEW_KEYPAIR: {

                apdu.setIncomingAndReceive();
                P256.generateNewKeypair();
                short len = P256.publicKey(buffer, (short)0);
                apdu.setOutgoingAndSend((short)0, len);
                break;
            }
            case INS_P256_ECDH: {
                short len = apdu.setIncomingAndReceive();
                short resLen = P256.ecdh(buffer, apdu.getOffsetCdata(), len, buffer, (short)0);
                P256.clean();
                apdu.setOutgoingAndSend((short)0, resLen);
                break;
            }
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
    }
}
