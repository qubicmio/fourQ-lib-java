package fourqj.api;

import fourqj.constants.Key;
import fourqj.crypto.core.Curve;
import fourqj.crypto.core.ECC;
import fourqj.crypto.primitives.HashFunction;
import fourqj.crypto.primitives.Kangaroo12;
import fourqj.exceptions.EncryptionException;
import fourqj.fieldoperations.FP;
import fourqj.types.data.F2Element;
import fourqj.types.point.ExtendedPoint;
import fourqj.types.point.FieldPoint;
import fourqj.utils.CryptoUtils;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Port of the C++ low-order (weak) public-key forgery tests introduced in
 * qubic/core PR #921 (test/fourq.cpp).
 * <p>
 * FourQ's group order is 392*r (cofactor 392 = 2^3 * 7^2, r = prime subgroup order).
 * Any public key whose order divides 392 lets an attacker forge a valid signature
 * without a private key, because h*A depends only on h mod (order of A). The identity
 * point is the worst case: a single deterministic (R,S) verifies for every message.
 * <p>
 * The identity encodes as {@code 01 00..00} (little-endian), which is also the QX
 * contract address. verify() must reject the whole cofactor subgroup.
 */
class SchnorrQLowOrderTest {

    private final HashFunction k12 = new Kangaroo12();
    private final SchnorrQ schnorrQ = new SchnorrQ(k12);

    // A legitimate key + signature (K12) reused as sanity positive control.
    // Same vector as SchnorrQK12Test.
    private static final BigInteger VALID_PUBLIC_KEY =
            new BigInteger("88b5035d1ba0860b1c26ae5a4a070a52f1596d10d816bad98862eb75f77f9fad", 16);
    private static final BigInteger VALID_SIGNATURE =
            new BigInteger("16d18a2f1a9f3403a5549f9fa3f0242458c077b22867d0db7bb6b8a23824fe1fae90b8df0b81858eb77058bf0928ad55247fa027e2cf6ee440b91ad839042300", 16);
    private static final byte[] VALID_MESSAGE =
            HexFormat.of().parseHex("da5fc4f10c7f3f020a02c1be37b96ba4987426aee9de2ad42351024feffb3302");

    // ---------------------------------------------------------------------------
    // Well-known low-order public keys, as raw 32-byte little-endian encodings
    // (mirrors kWeakKeys in the C++ tests). Each 64-bit limb is stored little-endian
    // starting at byte 0. See qubic/core PR #921.
    // ---------------------------------------------------------------------------
    private static final class WeakKey {
        final String name;
        final long[] limb; // 4 limbs, little-endian (limb[0] is bytes 0..7)
        WeakKey(String name, long l0, long l1, long l2, long l3) {
            this.name = name;
            this.limb = new long[] { l0, l1, l2, l3 };
        }
    }

    private static final WeakKey[] WEAK_KEYS = new WeakKey[] {
            new WeakKey("identity (0,1) order 1 (== QX address)", 1L, 0L, 0L, 0L),                          // fast-path
            new WeakKey("NULL_ID (i,0) order 4",                  0L, 0L, 0L, 0L),                          // general
            new WeakKey("(-i,0) order 4",                         0L, 0L, 0L, 0x8000000000000000L),         // general
            new WeakKey("(0,-1) order 2", 0xFFFFFFFFFFFFFFFEL, 0x7FFFFFFFFFFFFFFFL, 0L, 0L),                                     // general
    };

    /** Writes limbs little-endian into 32 bytes (byte 0 = LSB of limb 0). */
    private static byte[] weakKeyBytes(WeakKey w) {
        byte[] out = new byte[32];
        for (int li = 0; li < 4; li++) {
            long v = w.limb[li];
            for (int j = 0; j < 8; j++) {
                out[li * 8 + j] = (byte) ((v >>> (8 * j)) & 0xFF);
            }
        }
        return out;
    }

    /**
     * Converts 32-byte little-endian encoding into the {@code BigInteger} used by
     * {@link SchnorrQ#schnorrQVerify}. The library treats the pubkey/signature bytes
     * as a big-endian {@code BigInteger} whose byte layout matches the raw memory.
     */
    private static BigInteger leBytesToBigInteger(byte[] leBytes) {
        return new BigInteger(1, leBytes);
    }

    /**
     * Independent of verify(): does the key decode and is {@code [392]*A} the neutral
     * point? {@code true} iff A is a cofactor-subgroup (forgeable) point. Used to prove
     * the test vectors are genuinely low-order.
     */
    private static boolean isCofactorPoint(byte[] pubKeyLeBytes) {
        try {
            FieldPoint a = CryptoUtils.decode(leBytesToBigInteger(pubKeyLeBytes));
            ExtendedPoint p = Curve.pointSetup(a);
            p = Curve.cofactorClearing(p);        // p = 392 * A
            F2Element x = p.getX();
            BigInteger xr = FP.PUtil.fpMod1271(x.real);
            BigInteger xi = FP.PUtil.fpMod1271(x.im);
            return xr.signum() == 0 && xi.signum() == 0;
        } catch (EncryptionException e) {
            return false; // not a decodable curve point
        }
    }

    /**
     * Deterministic identity forgery: signature bytes = encode(S*G) || S (little-endian).
     * Uses the library's own {@code eccMulFixed} for the G term, so this is a genuine
     * forgery (valid absent the low-order guard).
     */
    private static BigInteger forgeIdentitySignature(long sLow) throws EncryptionException {
        BigInteger s = BigInteger.valueOf(sLow);
        // R = encode(S*G). CryptoUtils.encode() returns a big-endian BigInteger whose
        // 32-byte serialization is the LE-encoded point, which is exactly the layout
        // required for the first 32 bytes of the signature.
        BigInteger r = CryptoUtils.encode(ECC.eccMulFixed(s));

        // Build signature bytes: [R (32 bytes, as-is)] || [S (32 bytes, little-endian)].
        byte[] sig = new byte[64];
        byte[] rBytes = toFixed32BigEndian(r);
        System.arraycopy(rBytes, 0, sig, 0, 32);
        for (int j = 0; j < 8; j++) {
            sig[32 + j] = (byte) ((sLow >>> (8 * j)) & 0xFF);
        }
        return new BigInteger(1, sig);
    }

    private static byte[] toFixed32BigEndian(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        if (raw.length <= 32) {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        } else {
            // Strip a leading sign byte (should be 0).
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        }
        return out;
    }

    // ---------------------------------------------------------------------------
    // Sanity layer: the weak vectors really are cofactor-subgroup points, and a
    // legitimate key is not. Validates the vectors used by the rejection tests below
    // and exercises cofactor_clearing end-to-end.
    // ---------------------------------------------------------------------------
    @Test
    void testLowOrderVectorsAreCofactorPoints() {
        for (WeakKey w : WEAK_KEYS) {
            byte[] pk = weakKeyBytes(w);
            assertTrue(isCofactorPoint(pk), "expected low-order: " + w.name);
        }
        // Legitimate key must not be classified as low-order.
        byte[] legit = toFixed32LittleEndian(VALID_PUBLIC_KEY);
        assertFalse(isCofactorPoint(legit), "legitimate key misclassified as low-order");
    }

    private static byte[] toFixed32LittleEndian(BigInteger be) {
        // VALID_PUBLIC_KEY is given as a big-endian BigInteger whose 32-byte
        // serialization is the LE encoding of the point (this matches how the
        // library stores public keys). So a "LE bytes" view is just its 32-byte
        // BE serialization.
        return toFixed32BigEndian(be);
    }

    // ---------------------------------------------------------------------------
    // Headline forgery: the identity point {1,0,0,0} (== QX contract address) with a
    // single forged signature that is valid for EVERY message. verify() must reject
    // it for all of them. The positive control proves verify() is not trivially
    // returning false.
    // ---------------------------------------------------------------------------
    @Test
    void testVerifyRejectsIdentityForgery() throws EncryptionException {
        byte[] identityBytes = weakKeyBytes(WEAK_KEYS[0]);
        BigInteger identityPk = leBytesToBigInteger(identityBytes);

        // Positive control: a legitimate key + genuine signature still verifies.
        assertTrue(
                schnorrQ.schnorrQVerify(VALID_PUBLIC_KEY, VALID_SIGNATURE, VALID_MESSAGE),
                "sanity: valid signature must verify"
        );

        long[] scalars = { 1L, 2L, 123456789L };
        // A variety of messages/digests to demonstrate message-independence of the
        // identity forgery.
        byte[][] messages = new byte[][] {
                VALID_MESSAGE,
                HexFormat.of().parseHex("00"),
                HexFormat.of().parseHex("cb"),
                HexFormat.of().parseHex("aa5fc4f10c7f3f020a02c1be37b96ba4987426aee9de2ad42351024feffb3302"),
                fill32((byte) 0xAB),
        };

        for (long s : scalars) {
            BigInteger signature = forgeIdentitySignature(s);
            for (byte[] msg : messages) {
                assertFalse(
                        schnorrQ.schnorrQVerify(identityPk, signature, msg),
                        "identity forgery accepted (S=" + s + ")"
                );
            }
        }
    }

    private static byte[] fill32(byte b) {
        byte[] a = new byte[32];
        java.util.Arrays.fill(a, b);
        return a;
    }

    // ---------------------------------------------------------------------------
    // Defense in depth: verify() must reject every cofactor-subgroup public key,
    // whatever signature is presented. The guard fires right after decode(), before
    // the signature math. Each vector is first asserted to be genuinely low-order,
    // so the rejection is attributable to the weak-key guard.
    // ---------------------------------------------------------------------------
    @Test
    void testVerifyRejectsAllLowOrderPublicKeys() throws EncryptionException {
        BigInteger signature = forgeIdentitySignature(7L); // well-formed: R = encode(7*G), S = 7
        byte[] digest = fill32((byte) 0x5A);

        for (WeakKey w : WEAK_KEYS) {
            byte[] pkBytes = weakKeyBytes(w);
            assertTrue(isCofactorPoint(pkBytes), "test vector not low-order: " + w.name);
            BigInteger pk = leBytesToBigInteger(pkBytes);
            assertFalse(
                    schnorrQ.schnorrQVerify(pk, signature, digest),
                    "low-order public key accepted: " + w.name
            );
        }

    }

    // ---------------------------------------------------------------------------
    // Real forged transactions the attacker executed on network. Each is a full
    // Qubic transaction (source | dest | amount | tick | inputType | inputSize |
    // signature) that spends QU *from the identity point* {1,0,0,0} == 01 00..00 ==
    // the QX contract address, to attacker-controlled wallets. They passed the old
    // verify() and must now be rejected. The digest is reproduced exactly as the node
    // computes it in processBroadcastTransaction():
    //   KangarooTwelve(tx, totalSize - SIGNATURE_SIZE, digest, 32).
    // ---------------------------------------------------------------------------
    @Test
    void testVerifyRejectsNetworkForgeries() throws EncryptionException {
        final String[] networkForgeries = {
                "010000000000000000000000000000000000000000000000000000000000000091cfd01bb1d6b1d48e9f806a8ef65734ae6162fbb3b2643a0088c1046e55f776009435770000000072e878030000000052750c95db608b2ad33f260c13523f3392afdbeefcd071a824e3973403443d890f997c86e5c769fd2344c515a7ce19b4dffc30a06e6da2dab5a1bc09f2212300",
                "010000000000000000000000000000000000000000000000000000000000000091cfd01bb1d6b1d48e9f806a8ef65734ae6162fbb3b2643a0088c1046e55f776009435770000000060e8780300000000304d8a0eef6d5e578f7fe3623f21d97debd5c1a77a2bad8f347ae4cf41256a61f31cd9c1d5280e2895ba8d3864e7e33cb9197d7e0fca47e38211277fb2960b00",
                "01000000000000000000000000000000000000000000000000000000000000008220a28587c81abd47934c0f6e8af42d1b10182c494a3d46aa9908eaf83e606a00e40b5402000000e74a7803000000004c1357678e9aa76ef892379f94545e571a1435730c15b5ae366a1f34f9a8fa54834ba3e96e9c5b6407759e470b5ecceb5f233f067bbeecd72ebe0332b11f0200",
                "01000000000000000000000000000000000000000000000000000000000000008220a28587c81abd47934c0f6e8af42d1b10182c494a3d46aa9908eaf83e606a00f2052a01000000bf487803000000009f660e0561ec753b2d2395ef84a8b305489c091fbba0cfa95f910cc13d56e67f542412901ff6107611d2d4facf038fe73193a3f8b1dff646be0a9100ce752600",
                "01000000000000000000000000000000000000000000000000000000000000004de5b0cd0b1f9638e12b9906cc36a39334835644d958318957bb37b648b5822f01000000000000003917770300000000ef46106b7a44f73e67f857b8b9f66e4c2a0ed960453fe55a4058d0e4c4a052d679d773ae43ec0bc24e200ae4ce28abb5e0a195d45c313358719b0c77ae131c00",
                "0100000000000000000000000000000000000000000000000000000000000000d4902431eb401facb0e5f4c649b53801c3ad1228ba0294953922d2e662a66da301000000000000008d0d77030000000091f3a7dd1cf60d64a79efac0fe6f034a6848924a08f65d46059387a801761ebafc062f4764555f485fedbd34a7e536889d261582a46325cb5dd1e5b083412300",
                "01000000000000000000000000000000000000000000000000000000000000008220a28587c81abd47934c0f6e8af42d1b10182c494a3d46aa9908eaf83e606a01000000000000002b197703000000005cafd8c1dcf05b0eebf805cafb40d361848c13f94ce78640cfdb76fba0cddcde50ce8556637fdac894848fa18b18b5fdcbc49b0719ef505fcafe3100497f2200",
                "01000000000000000000000000000000000000000000000000000000000000008220a28587c81abd47934c0f6e8af42d1b10182c494a3d46aa9908eaf83e606a00e40b5402000000a0437703000000009573ad5ce6f0e8d8d02a28297334c3009a319580e63c27c5a1b257fe2e056fcc0b8307956b52c223eba07eb5a8a0384ba044626aed71637ef3238ad3ee160c00"
        };

        byte[] identity = new byte[32];
        identity[0] = 1;

        for (int i = 0; i < networkForgeries.length; i++) {
            byte[] tx = HexFormat.of().parseHex(networkForgeries[i]);
            assertTrue(tx.length >= 80 + 64, "vector " + i + " too short to be a transaction");

            // The spent-from account is the identity / QX address.
            for (int j = 0; j < 32; j++) {
                assertEquals(identity[j], tx[j], "vector " + i + " source is not the identity point");
            }
            // ... and it is a low-order point.
            byte[] sourcePkBytes = java.util.Arrays.copyOfRange(tx, 0, 32);
            assertTrue(isCofactorPoint(sourcePkBytes), "vector " + i + " source is not a cofactor point");

            // Digest exactly as the node computes it: K12 over everything but the 64-byte signature.
            int digestLen = tx.length - 64;
            byte[] digestInput = java.util.Arrays.copyOfRange(tx, 0, digestLen);
            byte[] digest = k12.computeHash(digestInput, false);
            byte[] signatureBytes = java.util.Arrays.copyOfRange(tx, digestLen, tx.length);

            BigInteger pk = leBytesToBigInteger(sourcePkBytes);
            BigInteger signature = new BigInteger(1, signatureBytes);

            // Independent structural check: for A = identity, verify (absent guards) accepts
            // iff encode(S*G) == R (since h*A == O). Confirm this really is a valid identity
            // forgery, so the rejection is attributable to the low-order guard, not to a
            // random signature mismatch.
            byte[] sLeBytes = java.util.Arrays.copyOfRange(signatureBytes, 32, 64);
            byte[] sBeBytes = new byte[32];
            for (int j = 0; j < 32; j++) sBeBytes[j] = sLeBytes[31 - j];
            BigInteger s = new BigInteger(1, sBeBytes);
            BigInteger rEncoded = CryptoUtils.encode(ECC.eccMulFixed(s));
            byte[] rBytes = toFixed32BigEndian(rEncoded);
            byte[] rFromSig = java.util.Arrays.copyOfRange(signatureBytes, 0, 32);
            assertArrayEquals(rBytes, rFromSig,
                    "vector " + i + " is not a valid identity forgery (encode(S*G) != R)");

            // The shipped verifier MUST reject it.
            assertFalse(
                    schnorrQ.schnorrQVerify(pk, signature, digest),
                    "FORGERY ACCEPTED for vector " + i + " -- the fix is NOT working"
            );

            // Silence unused warning for Key.SIGNATURE_SIZE etc.
            assertEquals(64, Key.SIGNATURE_SIZE);
        }
    }
}
