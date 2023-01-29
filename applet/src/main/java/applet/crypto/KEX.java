package applet.crypto;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;

// Key exchange. This class encapsulates functionality for ECDH key exchange and
// confirmation with authentication based on pre-shared key.
//
// # Design
// To simplify reading and understanding, the source code and documentation uses
// the standard conventions of names like Alice and Bob. Alice is a terminal or
// a client, which speaks to the Bob, which is a card (or in my case ring).
//
// The communication requires two rounds: key exchange and key confirmation.
// This design and implementation are inspired by the SPAKE2[1] algorithm, so
// KEX shares some similarities, but instead of using complicated password based
// key exchange, it uses much simpler one based on preshared key.
//
// The exchange goes as follows:
//
// 1. Alice and Bob have identifiers (aliceID and bobID).
//
// 2. Alice and Bob share a pre-shared key (PSK) of sufficient length.
//
// 3. Alice generates a P256 keypair and sends her public key (alicePub) to Bob
//    encoded in SEC1 format.
//
// 4. Bob genereates a P256 keypair and sends his public key (bobPub) to Alice
//    encoded in SEC1 format.
//
// 5. Both derive a shared secret with ECDH. Due to the retardness of javacards,
//    and old firmware on the ring, only SHA1 hash of the shared point is
//    available, so it's used here instead.
//
// 6. Both create a string called a transcript (TT):
//
//    TT = len(aliceID)          || aliceId          ||
//         len(bobID)            || bobID            ||
//         len(alicePub)         || alicePub         ||
//         len(bobPub)           || bobPub           ||
//         len(sha1SharedPoint)  || sha1SharedPoint  ||
//         len(PSK)              || PSK
//
// 7. The transcript is hashed with SHA256 and split into shared secret and
//    authentication key material:
//
//    sharedSecret, authKeyMaterial = SHA256(TT)
//
// 8. Alice and Bob also have a context -- a shared piece of data whose
//    integrity and authenticity can be additionally verified.
//
// 9. Both derive two additional keys: authKeyA and authKeyB with HKDF-SHA256.
//    A SHA512 hash of the context is used as part of info field. The result is
//    split into the auth keys.
//
//    contextHash = SHA512("ConfirmationKeys" || context)
//    authKeyA || authKeyB = HKDF(authKeyMaterial, salt='', info=contextHash, outLength=32)
//
// 10. Both derive confirmation tags: tagA and tagB using appropriate
//     authentication keys and transcript. The algorithm is HMAC-SHA256.
//
//     tagA = HMAC(authKeyA, TT)
//     tagB = HMAC(authKeyB, TT)
//
// 11. Alice sends tagA to Bob.
// 12. Bob verifies the tagA. If it's correct, Bob sends tagB to Alice.
// 13. Alice verifies the tagB.
// 14. If everything is correct, the sharedSecret is used as an output of the
//     algorithm.
//
// Schematically:
//
//                     +------------------+       +------------+
//                     | Alice (Terminal) |       | Bob (Card) |
//                     +------------------+       +------------+
//                               |                       |
//                               | Alice's public key    |
//                               |---------------------->|
//                               |                       | -------\
//                               |                       |-| ECDH |
//                               |                       | |------|
//                               |                       |
//                               |      Bob's public key |
//                               |<----------------------|
//                      -------\ |                       |
//                      | ECDH |-|                       |
//                      |------| |                       |
// ----------------------------\ |                       |
// | Derive confirmation tag A |-|                       |
// |---------------------------| |                       |
//                               |                       |
//                               | confirmation tag A    |
//                               |---------------------->|
//                               |                       | ----------------------------\
//                               |                       |-| Verify confirmation tag A |
//                               |                       | |---------------------------|
//                               |                       | ----------------------------\
//                               |                       |-| Derive confirmation tag B |
//                               |                       | |---------------------------|
//                               |                       |
//                               |    confirmation tag B |
//                               |<----------------------|
// ----------------------------\ |                       |
// | Verify confirmation tag B |-|                       |
// |---------------------------| |                       |
//                               |                       |
//
// [1]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-spake2/
//
// # Usage
// KEX expects a specific order of call methods though it doesn't validate them
// internally. Instead, the class relies on a user to keep the track of the
// state and call appropriate methods without messing everything up. From this
// perspective, the class can be seend as a set of utilities for integrating
// into the higher system.
//
// The order of calls is as follows:
//
// 1. start - accepts aliceId and BobId. Inits the state.
// 2. exchange - accepts alicePub and output bobPub.
// 3. setSharedKey - set preshared key. This should go only after the exchange.
// 4. appendContext - this method feeds data to the context hash function.
//    Can be called repeatedly and between any previous methods. It's only
//    important to stop feeding the context data before the next step.
// 5. confirm - accepts tagA. If it's correct, outputs tagB.
// 6. sharedSecret - outputs a shared secret.
// 7. clean - remove all secrets and reset the state.
//
public class KEX {
    public static final short MAX_TRANSCRIPT_LEN = 256;

    private static final short KEY_LEN = 16;
    private static final short CONTEXT_HASH_LEN = 64;
    public static final short TAG_SIZE = HmacSha256.HMAC_SIZE;

    public static final short REQUIRED_BUFFER_LEN = (short) (MAX_TRANSCRIPT_LEN
            + KEY_LEN * 4
            + CONTEXT_HASH_LEN
            + TAG_SIZE);

    // buffer consists of
    // - transcript (256 bytes)
    // - shared secret (16 bytes)
    // - auth key material (16 bytes)
    // - auth key A (16 bytes)
    // - auth key B (16 bytes)
    // - context hash (64 bytes)
    // - tag buffer (32 bytes)
    //
    private static byte[] buffer;
    private static short transcriptOffset;
    private static short bufferStart;
    private static short transcriptCapacity;
    // TODO: this variable changes a lot, move it to the ram
    private static short transcriptLen;

    private static short sharedPointHashOffset;

    private static short sharedSecretOffset;
    private static short authKmOffset;
    private static short authKeyAOffset;
    private static short authKeyBOffset;
    private static short contextHashOffset;
    private static short tagOffset;

    public static final short DATA_TOO_BIG = 0x2929;
    public static final short TRANSCRIPT_OVERFLOW = 0x7923;
    public static final short CRYPTO_ERROR = (short) 0xfe97;

    private static MessageDigest sha256;
    private static MessageDigest contextCollector;

    private static final byte[] confirmationKeys = { 'C', 'o', 'n', 'f', 'i', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'K',
            'e', 'y', 's' };

    // TODO: come up
    private static final byte[] hkdfSalt = {};

    public static void init() {
        buffer = JCSystem.makeTransientByteArray(REQUIRED_BUFFER_LEN, JCSystem.CLEAR_ON_DESELECT);

        bufferStart = 0;

        transcriptOffset = bufferStart;
        transcriptCapacity = MAX_TRANSCRIPT_LEN;
        transcriptLen = 0;

        // Shared point will be placed temporarily to copy it to the transcript
        // We will reuse that place for shared secret key
        sharedPointHashOffset = MAX_TRANSCRIPT_LEN;
        sharedSecretOffset = MAX_TRANSCRIPT_LEN;

        authKmOffset = (short) (sharedSecretOffset + KEY_LEN);
        authKeyAOffset = (short) (authKmOffset + KEY_LEN);
        authKeyBOffset = (short) (authKeyAOffset + KEY_LEN);
        contextHashOffset = (short) (authKeyBOffset + KEY_LEN);
        tagOffset = (short) (contextHashOffset + CONTEXT_HASH_LEN);

        sha256 = MessageDigest.getInstance(
                MessageDigest.ALG_SHA_256,
                false // externalAccess
        );

        contextCollector = MessageDigest.getInstance(
                MessageDigest.ALG_SHA_512,
                false // externalAccess
        );
    }

    private static void appendTranscript(byte[] data, short offset, short len) {
        // Just as debug assertion
        if (len > 127) {
            CryptoException.throwIt(DATA_TOO_BIG);
        }

        if ((short) (transcriptLen + len + 1) >= transcriptCapacity) {
            CryptoException.throwIt(TRANSCRIPT_OVERFLOW);
        }

        short transcriptEnd = (short) (transcriptOffset + transcriptLen);

        buffer[transcriptEnd] = (byte) len;
        transcriptEnd++;

        Util.arrayCopyNonAtomic(
                data, offset, // src
                buffer, transcriptEnd, // dest
                len);

        transcriptLen += len + 1;
    }

    public static void appendContext(byte[] data, short offset, short len) {
        contextCollector.update(data, offset, len);
    }

    public static void start(byte[] alice, short aliceOffset, short aliceLen, byte[] bob, short bobOffset,
            short bobLen) {
        appendTranscript(alice, aliceOffset, aliceLen);
        appendTranscript(bob, bobOffset, bobLen);

        contextCollector.reset();
        appendContext(confirmationKeys, (short) 0, (short) confirmationKeys.length);
    }

    public static short exchange(byte[] alicePub, short alicePubOffset, short alicePubLen, byte[] outBobPub,
            short outBobOffset) {
        appendTranscript(alicePub, alicePubOffset, alicePubLen);

        P256.generateNewKeypair();
        short sharedPointHashLen = P256.ecdh(alicePub, alicePubOffset, alicePubLen, buffer, sharedPointHashOffset);

        short bobLen = P256.publicKey(outBobPub, outBobOffset);
        appendTranscript(outBobPub, outBobOffset, bobLen);
        appendTranscript(buffer, sharedPointHashOffset, sharedPointHashLen);

        Util.arrayFillNonAtomic(buffer, sharedPointHashOffset, sharedPointHashLen, (byte) 0x00);

        return bobLen;
    }

    public static void setPresharedKey(byte[] key, short offset, short len) {
        appendTranscript(key, offset, len);
    }

    public static short confirm(byte[] aliceTag, short aliceTagOffset, short aliceTagLen, byte[] out, short outOffset) {
        if (aliceTagLen != TAG_SIZE) {
            CryptoException.throwIt(CRYPTO_ERROR);
        }

        // Finish context calculation
        contextCollector.doFinal(confirmationKeys, (short) 0, (short) 0, // empty string
                buffer, contextHashOffset); // dst
        contextCollector.reset();

        // Derive shared secret and auth key material
        sha256.reset();
        sha256.doFinal(buffer, transcriptOffset, transcriptLen,
                buffer, sharedSecretOffset);
        sha256.reset();

        // Derive both authentication keys
        HKDF.startExtract(hkdfSalt, (short) 0, (short) hkdfSalt.length);
        HKDF.extractUpdate(buffer, authKmOffset, KEY_LEN);
        HKDF.extractFinish();

        HKDF.expand(buffer, contextHashOffset, CONTEXT_HASH_LEN, // info
                buffer, authKeyAOffset, (short) (KEY_LEN + KEY_LEN) // dest, it will fill both keys: A and B
        );

        HKDF.clean();

        // Derive tag A
        HmacSha256.start(buffer, authKeyAOffset, KEY_LEN);
        HmacSha256.update(buffer, transcriptOffset, transcriptLen);
        HmacSha256.finalize(buffer, tagOffset);
        HmacSha256.clean();

        if (!Utils.const_eq(buffer, tagOffset, aliceTag, aliceTagOffset, TAG_SIZE)) {
            CryptoException.throwIt(CRYPTO_ERROR);
        }

        // Derive tag B
        HmacSha256.start(buffer, authKeyBOffset, KEY_LEN);
        HmacSha256.update(buffer, transcriptOffset, transcriptLen);
        HmacSha256.finalize(out, outOffset);
        HmacSha256.clean();

        return TAG_SIZE;
    }

    public static short sharedSecret(byte[] out, short offset) {
        Util.arrayCopyNonAtomic(
                buffer, sharedSecretOffset,
                out, offset,
                KEY_LEN);
        clean();
        return KEY_LEN;
    }

    public static void clean() {
        sha256.reset();
        contextCollector.reset();
        Util.arrayFillNonAtomic(buffer, bufferStart, REQUIRED_BUFFER_LEN, (byte) 0x00);
        transcriptLen = 0;
    }
}
