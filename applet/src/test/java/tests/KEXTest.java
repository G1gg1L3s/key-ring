package tests;

import applet.crypto.CryptoApplet;
import at.favre.lib.crypto.HKDF;
import common.Utils;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.jetbrains.annotations.NotNull;
import org.junit.Assert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class KEXTest extends CryptoBase {
    public static final int SW_UNKNOWN = 0x6f00;

    ResponseAPDU start(byte[] aliceId, byte[] bobId) throws Exception {
        Assert.assertEquals(aliceId.length, 16);
        Assert.assertEquals(bobId.length, 16);
        CommandAPDU apdu = new CommandAPDU(0x00, CryptoApplet.INS_KEX_START, 0x00, 0x00, Utils.concat(aliceId, bobId));
        ResponseAPDU res = card.transmit(apdu);
        Assert.assertEquals(Integer.toHexString(SW_SUCCESS), Integer.toHexString(res.getSW()));
        return res;
    }

    ResponseAPDU exchange(byte[] alicePub) throws Exception {
        CommandAPDU apdu = new CommandAPDU(0x00, CryptoApplet.INS_KEX_EXCHANGE, 0x00, 0x00, alicePub);
        ResponseAPDU res = card.transmit(apdu);
        Assert.assertEquals(Integer.toHexString(SW_SUCCESS), Integer.toHexString(res.getSW()));
        return res;
    }

    ResponseAPDU setPresharedKey(byte[] key) throws Exception {
        CommandAPDU apdu = new CommandAPDU(0x00, CryptoApplet.INS_KEX_SET_PRESHARED_KEY, 0x00, 0x00, key);
        ResponseAPDU res = card.transmit(apdu);
        Assert.assertEquals(Integer.toHexString(SW_SUCCESS), Integer.toHexString(res.getSW()));
        return res;
    }

    ResponseAPDU appendContext(byte[] data) throws Exception {
        CommandAPDU apdu = new CommandAPDU(0x00, CryptoApplet.INS_KEX_APPEND_CONTEXT, 0x00, 0x00, data);
        ResponseAPDU res = card.transmit(apdu);
        Assert.assertEquals(Integer.toHexString(SW_SUCCESS), Integer.toHexString(res.getSW()));
        return res;
    }

    ResponseAPDU confirm(byte[] tag) throws Exception {
        CommandAPDU apdu = new CommandAPDU(0x00, CryptoApplet.INS_KEX_CONFIRM, 0x00, 0x00, tag);
        ResponseAPDU res = card.transmit(apdu);
        return res;
    }

    ResponseAPDU sharedSecret() throws Exception {
        CommandAPDU apdu = new CommandAPDU(0x00, CryptoApplet.INS_KEX_SHARED_SECRET, 0x00, 0x00, new byte[] {});
        ResponseAPDU res = card.transmit(apdu);
        Assert.assertEquals(Integer.toHexString(SW_SUCCESS), Integer.toHexString(res.getSW()));
        return res;
    }

    ResponseAPDU clean() throws Exception {
        CommandAPDU apdu = new CommandAPDU(0x00, CryptoApplet.INS_KEX_CLEAN, 0x00, 0x00, new byte[] {});
        ResponseAPDU res = card.transmit(apdu);
        Assert.assertEquals(Integer.toHexString(SW_SUCCESS), Integer.toHexString(res.getSW()));
        return res;
    }

    public static ECPublicKey loadPublicKey(byte[] data)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        ECParameterSpec ecParameterSpec = getParameterSpec();
        ECPublicKeySpec publicKey = new ECPublicKeySpec(ecParameterSpec.getCurve().decodePoint(data), ecParameterSpec);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        return (ECPublicKey) kf.generatePublic(publicKey);
    }

    public static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        ECParameterSpec ecSpec = getParameterSpec();
        keyGen.initialize(ecSpec, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    public static byte[] encodePublic(KeyPair pair) {
        return ((BCECPublicKey) pair.getPublic()).getQ().getEncoded(false);
    }

    public static byte[] javacardECDH(KeyPair alice, ECPublicKey bob) throws Exception {
        KeyAgreement agree = KeyAgreement.getInstance("ECDH", "BC");
        agree.init(alice.getPrivate());
        agree.doPhase(bob, true);

        MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
        return hash.digest(agree.generateSecret());
    }

    public static byte[] getContextHash(byte[] context) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest hash = MessageDigest.getInstance("SHA512", "BC");
        hash.update("ConfirmationKeys".getBytes());
        hash.update(context);
        return hash.digest();
    }

    static Keys deriveKeys(byte[] transcript, byte[] salt, byte[] contextHash) throws Exception {
        byte[] keys = MessageDigest.getInstance("SHA256", "BC").digest(transcript);
        byte[] sharedSecret = Arrays.copyOfRange(keys, 0, 16);
        byte[] authKeyMaterial = Arrays.copyOfRange(keys, 16, 32);

        byte[] prf = HKDF.fromHmacSha256().extract(salt, authKeyMaterial);
        byte[] authKeys = HKDF.fromHmacSha256().expand(prf, contextHash, 32);
        byte[] authKeyA = Arrays.copyOfRange(authKeys, 0, 16);
        byte[] authKeyB = Arrays.copyOfRange(authKeys, 16, 32);
        return new Keys(sharedSecret, authKeyA, authKeyB);
    }

    @Test
    void basicUsage() throws Exception {
        byte[] aliceId = Utils.parseHex("f87165e305b0f7c4824d3806434f9d09");
        byte[] bobId = Utils.parseHex("1a1707bb54e5fb4deddd19f07adcb4f1");
        byte[] context = Utils.parseHex("d180d183d181d0bdd19620d0bfd196d0b7d0b4d0b0");
        byte[] presharedKey = Utils.parseHex("9060c103d4f27cd1ac4d3c6eb0a979db41f86003b0fffa32c6f96813aba55737");
        byte[] salt = Utils.parseHex("");

        KeyPair alice = newKeyPair();
        byte[] alicePub = encodePublic(alice);

        TranscriptBuilder transcriptBuilder = new TranscriptBuilder()
                .append(aliceId)
                .append(bobId)
                .append(alicePub);

        start(aliceId, bobId);

        ResponseAPDU exchangeResponse = exchange(alicePub);

        transcriptBuilder.append(exchangeResponse.getData());
        ECPublicKey bobPub = loadPublicKey(exchangeResponse.getData());

        byte[] sharedPointHash = javacardECDH(alice, bobPub);
        transcriptBuilder
                .append(sharedPointHash)
                .append(presharedKey);

        byte[] transcript = transcriptBuilder.build();
        byte[] contextHash = getContextHash(context);

        setPresharedKey(presharedKey);
        appendContext(context);

        Keys keys = deriveKeys(transcript, salt, contextHash);
        byte[] tagA = hmacSha256(keys.authKeyA, transcript);

        byte[] tagBExpected = hmacSha256(keys.authKeyB, transcript);
        ResponseAPDU tagB = confirm(tagA);
        Assert.assertEquals(Integer.toHexString(SW_SUCCESS), Integer.toHexString(tagB.getSW()));
        byte[] tagBReceived = tagB.getData();

        // NOTE: this operation is UNSAFE. Comparing secrets should be in constant time
        // manner
        Assertions.assertEquals(Utils.toHex(tagBExpected), Utils.toHex(tagBReceived));

        byte[] sharedSecretReceived = sharedSecret().getData();
        Assertions.assertEquals(Utils.toHex(keys.sharedSecret), Utils.toHex(sharedSecretReceived));

        clean();
    }

    @Test
    void presharedKeyIsWrong() throws Exception {
        byte[] aliceId = Utils.parseHex("f87165e305b0f7c4824d3806434f9d09");
        byte[] bobId = Utils.parseHex("1a1707bb54e5fb4deddd19f07adcb4f1");
        byte[] context = Utils.parseHex("d180d183d181d0bdd19620d0bfd196d0b7d0b4d0b0");
        byte[] presharedKeyAlice = Utils.parseHex("9060c103d4f27cd1ac4d3c6eb0a979db41f86003b0fffa32c6f96813aba55737");
        byte[] presharedKeyBob = Utils.parseHex("9060c103d3f27cd1ac4d3c6eb0a979db41f86003b0fffa32c6f96813aba55737");
        byte[] salt = Utils.parseHex("");

        KeyPair alice = newKeyPair();
        byte[] alicePub = encodePublic(alice);

        TranscriptBuilder transcriptBuilder = new TranscriptBuilder()
                .append(aliceId)
                .append(bobId)
                .append(alicePub);

        start(aliceId, bobId);

        ResponseAPDU exchangeResponse = exchange(alicePub);

        transcriptBuilder.append(exchangeResponse.getData());
        ECPublicKey bobPub = loadPublicKey(exchangeResponse.getData());

        byte[] sharedPointHash = javacardECDH(alice, bobPub);
        transcriptBuilder
                .append(sharedPointHash)
                .append(presharedKeyAlice);

        byte[] transcript = transcriptBuilder.build();
        byte[] contextHash = getContextHash(context);

        setPresharedKey(presharedKeyBob);
        appendContext(context);

        Keys keys = deriveKeys(transcript, salt, contextHash);
        byte[] tagA = hmacSha256(keys.authKeyA, transcript);

        ResponseAPDU tagB = confirm(tagA);
        Assert.assertNotEquals(Integer.toHexString(SW_SUCCESS), Integer.toHexString(tagB.getSW()));
        clean();
    }

    @Test
    void contextIsWrong() throws Exception {
        byte[] aliceId = Utils.parseHex("f87165e305b0f7c4824d3806434f9d09");
        byte[] bobId = Utils.parseHex("1a1707bb54e5fb4deddd19f07adcb4f1");
        byte[] contextAlice = Utils.parseHex("d180d183d181d0bdd19620d0bfd196d0b7d0b4d0b0");
        byte[] contextBob = Utils.parseHex("d180d183d181d0bdd19620d0bfd196d0b7d0b4d0b000");
        byte[] presharedKey = Utils.parseHex("9060c103d4f27cd1ac4d3c6eb0a979db41f86003b0fffa32c6f96813aba55737");
        byte[] salt = Utils.parseHex("");

        KeyPair alice = newKeyPair();
        byte[] alicePub = encodePublic(alice);

        TranscriptBuilder transcriptBuilder = new TranscriptBuilder()
                .append(aliceId)
                .append(bobId)
                .append(alicePub);

        start(aliceId, bobId);

        ResponseAPDU exchangeResponse = exchange(alicePub);

        transcriptBuilder.append(exchangeResponse.getData());
        ECPublicKey bobPub = loadPublicKey(exchangeResponse.getData());

        byte[] sharedPointHash = javacardECDH(alice, bobPub);
        transcriptBuilder
                .append(sharedPointHash)
                .append(presharedKey);

        byte[] transcript = transcriptBuilder.build();
        byte[] contextHash = getContextHash(contextAlice);

        setPresharedKey(presharedKey);
        appendContext(contextBob);

        Keys keys = deriveKeys(transcript, salt, contextHash);
        byte[] tagA = hmacSha256(keys.authKeyA, transcript);

        ResponseAPDU tagB = confirm(tagA);
        Assert.assertNotEquals(Integer.toHexString(SW_SUCCESS), Integer.toHexString(tagB.getSW()));
        clean();
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        final String ALGORITHM = "HmacSHA256";
        Mac hmacSha256 = Mac.getInstance(ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        hmacSha256.init(secretKey);
        return hmacSha256.doFinal(data);
    }

    @NotNull
    public static ECParameterSpec getParameterSpec() {
        X9ECParameters params = CustomNamedCurves.getByName("secp256r1");
        ECParameterSpec ecParameterSpec = new ECParameterSpec(params.getCurve(), params.getG(), params.getN(),
                params.getH(), params.getSeed());
        return ecParameterSpec;
    }
}

class Keys {
    byte[] sharedSecret;
    byte[] authKeyA;
    byte[] authKeyB;

    public Keys(byte[] sharedSecret, byte[] authKeyA, byte[] authKeyB) {
        this.sharedSecret = sharedSecret;
        this.authKeyA = authKeyA;
        this.authKeyB = authKeyB;
    }
}

class TranscriptBuilder {
    ByteArrayOutputStream transcript = new ByteArrayOutputStream();

    TranscriptBuilder append(byte[] chunk) throws IOException {
        byte len = (byte) chunk.length;

        transcript.write(len);
        transcript.write(chunk);

        return this;
    }

    byte[] build() {
        return transcript.toByteArray();
    }
}
