package tests;

import applet.crypto.CryptoApplet;
import common.Utils;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.jetbrains.annotations.NotNull;
import org.junit.Assert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyAgreement;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;


import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class P256Test extends CryptoBase {
    public static final int SW_UNKNOWN = 0x6f00;


    ResponseAPDU generateNewKeypair() {
        CommandAPDU apdu = new CommandAPDU(0x00, CryptoApplet.INS_P256_GENERATE_NEW_KEYPAIR, 0x00, 0x00, new byte[] {});
        return card.transmitCommand(apdu);
    }

    ResponseAPDU ecdh(byte[] pubkey) {
        CommandAPDU apdu = new CommandAPDU(0x00, CryptoApplet.INS_P256_ECDH, 0x00, 0x00, pubkey);
        return card.transmitCommand(apdu);
    }

    @Test
    void generateKeyPairTest() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        ResponseAPDU response = generateNewKeypair();
        Assert.assertEquals(SW_SUCCESS, response.getSW());
        byte[] encoded = response.getData();

        // Will throws an error if the point is wrong
        loadPublicKey(encoded);
    }

    @Test
    void ecdhTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        ECParameterSpec ecSpec = getParameterSpec();
        keyGen.initialize(ecSpec, new SecureRandom());


        ResponseAPDU response = generateNewKeypair();
        Assert.assertEquals(SW_SUCCESS, response.getSW());
        byte[] bobPublic = response.getData();

        System.out.println("Bob public: " + Utils.toHex(bobPublic));

        ECPublicKey bob = loadPublicKey(bobPublic);

        KeyPair alice = keyGen.generateKeyPair();
        KeyAgreement aliceAgree = KeyAgreement.getInstance("ECDH", "BC");
        aliceAgree.init(alice.getPrivate());

        aliceAgree.doPhase(bob, true);

        MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aliceShared = hash.digest(aliceAgree.generateSecret());

        byte[] alicePub = ((BCECPublicKey) alice.getPublic()).getQ().getEncoded(false);

        System.out.println("Alice public: " + Utils.toHex(alicePub));

        response = ecdh(alicePub);
        Assertions.assertEquals(SW_SUCCESS, response.getSW());
        byte[] bobShared = response.getData();

        Assert.assertEquals(Utils.toHex(aliceShared), Utils.toHex(bobShared));
    }

    void testWith(String maliciousPublicKey) {
        ResponseAPDU response = generateNewKeypair();
        Assert.assertEquals(SW_SUCCESS, response.getSW());

        byte[] alicePub = Utils.parseHex(maliciousPublicKey);
        response = ecdh(alicePub);

        Assertions.assertEquals(SW_UNKNOWN, response.getSW());
    }

    @Test
    void XEqualPCompressed() {
        testWith("03ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    }

    @Test
    void XYEqualP() {
        testWith("04ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    }


    @Test
    void XGreaterThanPCompressed() {
        testWith("02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    }

    @Test
    void XYGreaterThanP() {
        testWith("04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    }

    @Test
    void XNotOnCurveCompressed() {
        testWith("02ae2336ae573e1418b544cf930b37c0c57bf047096aa7218b5786ec8ef53a228e");
    }

    @Test
    void XYNotOnCurve() {
        Assumptions.assumeFalse(isSimulator);
        testWith("04a1a0f443179fbc06ee046af7e8a9f27f50f129d9df32a77f4ed7a641ffb86367f610e2449c9c07af47a1f425d3ac513fbeee634066d456dea315c256544a7b48");
    }

    public static ECPublicKey loadPublicKey(byte[] data)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        ECParameterSpec ecParameterSpec = getParameterSpec();
        ECPublicKeySpec publicKey = new ECPublicKeySpec(ecParameterSpec.getCurve().decodePoint(data), ecParameterSpec);
        KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        return (ECPublicKey) kf.generatePublic(publicKey);
    }

    @NotNull
    public static ECParameterSpec getParameterSpec() {
        X9ECParameters params = CustomNamedCurves.getByName("secp256r1");
        ECParameterSpec ecParameterSpec = new ECParameterSpec(params.getCurve(), params.getG(), params.getN(),
                params.getH(), params.getSeed());
        return ecParameterSpec;
    }
}
