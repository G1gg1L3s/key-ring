package applet.crypto;

import javacard.framework.Util;
import javacard.security.RandomData;

// This class encapsulates a bunch of tradeoffs for random number generator.
// It was designed to satisfy the following goals:
// 1. Do not create pressure on EEPROM
// 2. Do not use RandomData(ALG_SECURE_RANDOM) frequently, as the card,
//    that I use, burns very quickly because of it.
//    (See https://github.com/mclear/OMNI-Ring/issues/5)
// 3. Be secure as possible. It includes forward secrecy, recover from the state compromise
//    and be resistant to the possible backdoors or errors in hardware rng.
//
// The algorithm:
// The rng stores a 32 byte seed in its EEPROM, which is provided during
// installation by the user.
// When the applet it selected, new session key is created and stored in ram:
//
// ```
// reseed:
//     nonce = hardwareRNG(16)
//     session_key = hmac(seed, nonce || 'session')
//     new_seed = hmac(seed, nonce || 'seed')
// ```
//
// The seed is then replaced by the `new_seed`.
//
// A 1-byte counter is stored together with the session_key.
// To generate random bytes for the user, the rng generates 32-byte blocks:
//
// ```
// next32:
//     next_bytes = hmac(session_key, 'random' || counter)
//     counter += 1
// ```
// After 255 calls to next32, the rng is reseeded again. This design is inspired by the HKDF.
//
// Such design achieves all the required goals:
// 1. Writing to EEPROM happens during select and every 255*32 bytes,
//    which should be enough for one session. The same for RandomData(ALG_SECURE_RANDOM).
// 2. RandomData(ALG_SECURE_RANDOM) is used to recover from state compromise and provide
//    backward secrecy. But it's mixed with other sources in case its implementation
//    is flawful or backdoored. Forward secrecy is achieved by replacing old seed with
//    a new one.
public class Rng {
    // Seed is a static value, that is stored in EEPROM.
    // It's provided by the user during the applet installation.
    // It's combined with RandomData(ALG_SECURE_RANDOM) to produce a
    // Session key.
    public static final short SEED_SIZE = 32;

    // Session key is an RNG key, generated during the `select` and updated
    // every 32*255 bytes. It's stored in RAM to provide less pressure on the EEPROM
    // and generates bytes only for the current session.
    private static final short SESSION_KEY_SIZE = 32;

    // Counter is combined with a session key to produce random bytes.
    private static final short COUNTER_SIZE = 1;

    // Block is a temporal storage for random bytes, before they are copied into
    // the user's buffer. Its size is equal to HMAC-SHA256 output size.
    private static final short BLOCK_SIZE = 32;

    // Nonce is a value from RandomData(ALG_SECURE_RANDOM), which is combined
    // with the seed to produce session key.
    private static final short NONCE_SIZE = 16;

    public static final short REQUIRED_BUFFER_SIZE = SESSION_KEY_SIZE + COUNTER_SIZE + BLOCK_SIZE;

    private static final short SESSION_KEY_OFFSET = 0;
    private static final short COUNTER_OFFSET = SESSION_KEY_OFFSET + SESSION_KEY_SIZE;
    private static final short BLOCK_OFFSET = COUNTER_OFFSET + COUNTER_SIZE;

    private static final byte[] SEED_SALT = { 's', 'e', 'e', 'd' };
    private static final byte[] SESSION_SALT = { 's', 'e', 's', 's', 'i', 'o', 'n' };
    private static final byte[] GENERATOR_SALT = { 'r', 'a', 'n', 'd', 'o', 'm' };

    // Seed is a 32 byte key stored in EEPROM
    private static byte[] seed;

    // Buffer stores temporal session key and a buffer for generating bytes
    // This value is stored in RAM and updates frequently
    // [32-byte SESSION KEY] [1-byte counter] [32-byte buffer]
    private static byte[] buffer;

    private static RandomData rng;

    public static void init(byte[] seedBuff, byte[] buff) {
        seed = seedBuff;
        buffer = buff;
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    // Generates nonce and derives new seed and session key
    public static void reseed() {
        // 1. Generate nonce from crypto rng,
        // temporary store it in the block.
        rng.generateData(buffer, BLOCK_OFFSET, NONCE_SIZE);

        // 2. new_session_key = hmac(seed, nonce || seed_session)
        HmacSha256.start(seed, (short) 0, SEED_SIZE);
        HmacSha256.update(buffer, BLOCK_OFFSET, NONCE_SIZE);
        HmacSha256.update(SESSION_SALT, (short) 0, (short) SESSION_SALT.length);
        HmacSha256.finalize(buffer, SESSION_KEY_OFFSET);

        // 3. new_seed = hmac(seed, nonce || seed_info)
        HmacSha256.start(seed, (short) 0, SEED_SIZE);
        HmacSha256.update(buffer, BLOCK_OFFSET, NONCE_SIZE);
        HmacSha256.update(SEED_SALT, (short) 0, (short) SEED_SALT.length);
        HmacSha256.finalize(seed, (short) 0);

        // 4. Clear nonce
        Util.arrayFillNonAtomic(buffer, BLOCK_OFFSET, NONCE_SIZE, (byte) 0x00);

        // 5. clear counter
        buffer[COUNTER_OFFSET] = 0x01;
    }

    // Generates next 32 random bytes in the buffer[BLOCK]
    private static void update() {
        if (buffer[COUNTER_OFFSET] == 0x00) {
            reseed();
        }
        // Next block is hmac(session_key, salt || counter);
        HmacSha256.start(buffer, SESSION_KEY_OFFSET, SESSION_KEY_SIZE);
        HmacSha256.update(GENERATOR_SALT, (short) 0, (short) GENERATOR_SALT.length);
        HmacSha256.update(buffer, COUNTER_OFFSET, COUNTER_SIZE);
        HmacSha256.finalize(buffer, BLOCK_OFFSET);
        buffer[COUNTER_OFFSET] += 1;
    }

    // Fills the buffer with random bytes
    public static void fill(byte[] buff, short offset, short len) {
        short left = len;
        while (left > 0) {
            update();
            short copy_len = left < BLOCK_SIZE ? left : BLOCK_SIZE;
            Util.arrayCopyNonAtomic(
                    buffer, BLOCK_OFFSET, // src
                    buff, offset, // dest
                    copy_len // length
            );

            offset += copy_len;
            left -= copy_len;
        }
    }
}
