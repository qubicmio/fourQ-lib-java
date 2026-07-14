package fourqj.api;

import fourqj.constants.Key;
import fourqj.constants.Params;
import fourqj.exceptions.EncryptionException;
import fourqj.exceptions.InvalidArgumentException;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Ports the negative-verify and malleability tests introduced in
 * qubic/core commit 05f734899c8374f9d29d7df72fb3daf872c8d22f
 * (test/fourq.cpp: {@code TestVerifyRejectsTamperedSignature},
 * {@code TestVerifyRejectsMalleableSignature},
 * {@code TestVerifyRejectsScalarEqualToCurveOrder}).
 * <p>
 * The C++ hotfix replaced the composite upper-bound check
 * {@code (signature[62] & 0xC0) || signature[63]} (i.e. {@code S < 2^246})
 * with a strict canonical check {@code S < curve_order r}. The old check
 * left the malleability gap {@code [r, 2^246)} open: for any valid
 * {@code (R, S)}, the twin {@code S' = S + r} verifies for the same message
 * but produces a distinct transaction hash, enabling double-execution on
 * the network.
 * <p>
 * These tests use the Java SchnorrQ with the default SHA-512 hash (matching
 * the C++ signer/verifier). Vectors are generated deterministically via the
 * Java signer rather than mirroring the C++ subseed vectors verbatim, since
 * the Java {@code schnorrQSign} takes a secret key (not a subseed) — the
 * malleability/tampering properties being exercised are independent of the
 * exact input vectors.
 */
class SchnorrQMalleabilityTest {

    private final SchnorrQ schnorrQ = new SchnorrQ();

    /** Deterministic (secretKey, message) pairs used to exercise verify(). */
    private static final String[][] VECTORS = new String[][] {
            {
                    "4ac19e2bf0d3776519aabe31924f7dc2589b3d0e7411a65f84c9b16df72c038e",
                    "94e120a4d3f58c217a53eb9046d9f2c5b11288a9fe340d6ce5a771cf04b82e63"
            },
            {
                    "e8217c5b40aa91df662803ce4dbf18722e35f1097ac68fb5da10643a825799e3",
                    "77f493b58ea40162dc33f9a718e2543b05f629884d7ca0e31598c45f021ae7c0"
            },
            {
                    "6d02f48bcb53ac397fc71a9028e4165df9b87044c53e116a0192d7fa83254bb0",
                    "5cc82fa973101da5bfb3e2448196f0a7d7d3324c86fbbe42907613d5c8c2f1a4"
            },
            {
                    "3cfa1097be482f6e5ce132c2aa657d0fb9d84121048de6f05b90a2cc136bf73a",
                    "c01ae5f2879d11439b30ddae5f4c7b22689f023e17b4955c3b2f05e8d9089af6"
            },
    };

    /**
     * Builds a fresh (publicKey, digest, signature) triple where the signature verifies. The
     * signature is guaranteed well-formed (canonical S, valid public key) so it can be used
     * as a starting point for negative/malleability perturbations.
     */
    private SignedTriple makeValid(int i) throws EncryptionException {
        BigInteger secretKey = new BigInteger(VECTORS[i][0], 16);
        byte[] digest = HexFormat.of().parseHex(VECTORS[i][1]);
        BigInteger publicKey = schnorrQ.schnorrQKeyGeneration(secretKey);
        BigInteger signature = schnorrQ.schnorrQSign(secretKey, publicKey, digest);
        return new SignedTriple(publicKey, digest, signature);
    }

    // ---------------------------------------------------------------------------
    // TestVerifyRejectsTamperedSignature — mirrors qubic/core test/fourq.cpp.
    // For each vector: verify() must accept the untouched signature, and reject
    // every localized perturbation (flip a bit in R, flip a bit in S, wrong
    // digest, wrong public key).
    // ---------------------------------------------------------------------------
    @Test
    void testVerifyRejectsTamperedSignature() throws EncryptionException {
        for (int i = 0; i < VECTORS.length; i++) {
            SignedTriple v = makeValid(i);

            // Sanity: the untouched signature must verify.
            assertTrue(schnorrQ.schnorrQVerify(v.publicKey, v.signature, v.digest),
                    "valid signature rejected at vector [" + i + "]");

            // Flip a bit in the commitment R (top 256 bits of the signature): flip bit 256
            // which corresponds to the low bit of R's little-endian byte 0.
            BigInteger badR = v.signature.xor(BigInteger.ONE.shiftLeft(256));
            assertFalse(schnorrQ.schnorrQVerify(v.publicKey, badR, v.digest),
                    "tampered R accepted at vector [" + i + "]");

            // Flip a low bit in the scalar S. S occupies the low 256 bits stored in
            // reversed (little-endian) byte order; the low bit of the BigInteger
            // corresponds to the top bit of little-endian byte 31 of S. Any single-bit
            // flip in the S region yields a still-canonical, still-well-formed signature
            // that must nonetheless fail verification.
            BigInteger badS = v.signature.xor(BigInteger.ONE.shiftLeft(255));
            assertFalse(schnorrQ.schnorrQVerify(v.publicKey, badS, v.digest),
                    "tampered S accepted at vector [" + i + "]");

            // Wrong message digest.
            byte[] otherDigest = v.digest.clone();
            otherDigest[0] ^= 0x01;
            assertFalse(schnorrQ.schnorrQVerify(v.publicKey, v.signature, otherDigest),
                    "wrong digest accepted at vector [" + i + "]");

            // Wrong public key: sign the same message with the NEXT secret key and use
            // its (well-formed, on-curve) public key here — the signature is not valid
            // for it.
            SignedTriple other = makeValid((i + 1) % VECTORS.length);
            assertFalse(schnorrQ.schnorrQVerify(other.publicKey, v.signature, v.digest),
                    "wrong public key accepted at vector [" + i + "]");
        }
    }

    // ---------------------------------------------------------------------------
    // TestVerifyRejectsMalleableSignature — mirrors qubic/core test/fourq.cpp.
    //
    // For every valid (R, S), the twin S' = S + curve_order r is a second SchnorrQ
    // scalar that satisfies the verification equation s*G + H*A = R for the same
    // message and public key (because the scalar arithmetic is mod r). Before the
    // hotfix, verify() only enforced S < 2^246, so any twin whose top bytes still
    // fit in that range slipped through and produced a distinct transaction hash
    // — enabling double-execution.
    //
    // The strict canonical check S < r closes this: every twin has S' >= r and
    // must be rejected. Note that in the Java verifier, non-canonical S is
    // reported by throwing InvalidArgumentException (checked-exception hierarchy
    // rooted at EncryptionException) rather than returning false — both count as
    // "not accepted".
    // ---------------------------------------------------------------------------
    @Test
    void testVerifyRejectsMalleableSignature() throws EncryptionException {
        int testedTwins = 0;
        for (int i = 0; i < VECTORS.length; i++) {
            SignedTriple v = makeValid(i);
            assertTrue(schnorrQ.schnorrQVerify(v.publicKey, v.signature, v.digest),
                    "valid signature rejected at vector [" + i + "]");

            // Build twin S' = S + r; keep R unchanged.
            BigInteger twin = buildTwinSignature(v.signature);

            // Only twins that still fit past the OLD 2^246 check would have slipped
            // through pre-fix. Test that they are now rejected (via false OR exception).
            if (fitsOldSizeCheck(twin)) {
                testedTwins++;
                boolean accepted;
                try {
                    accepted = schnorrQ.schnorrQVerify(v.publicKey, twin, v.digest);
                } catch (InvalidArgumentException e) {
                    // Canonical check rejects with a "non-canonical" message.
                    assertTrue(e.getMessage().contains("non-canonical"),
                            "unexpected rejection message: " + e.getMessage());
                    accepted = false;
                }
                assertFalse(accepted,
                        "malleable twin S+r accepted at vector [" + i + "]");
            }
        }
        assertTrue(testedTwins > 0,
                "no test vector produced a twin in the malleable range — canonical check untested");
    }

    // ---------------------------------------------------------------------------
    // TestVerifyRejectsScalarEqualToCurveOrder — boundary case: S == r is exactly
    // non-canonical (the check is strict) and must be rejected.
    // ---------------------------------------------------------------------------
    @Test
    void testVerifyRejectsScalarEqualToCurveOrder() throws EncryptionException {
        SignedTriple v = makeValid(0);

        // Build a signature with S = r exactly (keep R untouched).
        BigInteger atOrder = replaceScalar(v.signature, Params.CURVE_ORDER);

        boolean accepted;
        try {
            accepted = schnorrQ.schnorrQVerify(v.publicKey, atOrder, v.digest);
        } catch (InvalidArgumentException e) {
            assertTrue(e.getMessage().contains("non-canonical"),
                    "unexpected rejection message: " + e.getMessage());
            accepted = false;
        }
        assertFalse(accepted, "scalar S == curve_order accepted");
    }

    // ---------------------------------------------------------------------------
    // Helpers — signature layout:
    //   signature (64 bytes big-endian in BigInteger) = R (32 bytes) || S (32 bytes),
    //   where R and S are each stored little-endian in the byte stream. Hence,
    //   in the BigInteger:
    //     - top 256 bits (signature.divide(2^256))   = R read as big-endian int
    //       (i.e. byte-reversed natural S value; we don't touch R here)
    //     - low 256 bits (signature.mod(2^256))      = the byte-reversal of the
    //       natural integer value of S.
    //   To install a new natural-integer S value: byte-reverse it into 32 bytes
    //   and use that as the low 256 bits.
    // ---------------------------------------------------------------------------

    /** Returns {@code signature} with its scalar component replaced by {@code newS} (a natural integer). */
    private static BigInteger replaceScalar(BigInteger signature, BigInteger newS) {
        BigInteger rPart = signature.divide(Key.POW_256).multiply(Key.POW_256);
        byte[] sBe = to32BytesBe(newS);
        byte[] sLe = reverse(sBe);
        BigInteger sLow = new BigInteger(1, sLe);
        return rPart.add(sLow);
    }

    /** Builds the malleable twin {@code (R, S + curve_order)} of a valid signature. */
    private static BigInteger buildTwinSignature(BigInteger signature) {
        BigInteger s = extractScalar(signature);
        BigInteger twinS = s.add(Params.CURVE_ORDER);
        // Guard: keep the twin representable in 32 bytes (it always is, since
        // s < r and r < 2^253, so s + r < 2^254).
        assertTrue(twinS.bitLength() <= 256, "twin scalar overflows 32 bytes");
        return replaceScalar(signature, twinS);
    }

    /** Extracts the natural integer value of the scalar S from a signature BigInteger. */
    private static BigInteger extractScalar(BigInteger signature) {
        BigInteger sLow = signature.mod(Key.POW_256);
        byte[] sLe = to32BytesBe(sLow); // low-256 in big-endian order == reversed S bytes
        byte[] sBe = reverse(sLe);
        return new BigInteger(1, sBe);
    }

    /** True iff the OLD pre-hotfix "S < 2^246" byte-level check would have accepted this signature. */
    private static boolean fitsOldSizeCheck(BigInteger signature) {
        // Old C++ check: reject if (signature[62] & 0xC0) || signature[63].
        // Mapped to the BigInteger: those bytes are the low 2 bytes when reading
        // the low-256-bit S region byte-reversed; equivalently, bits 0..7 (byte 63)
        // and bits 14..15 (top 2 bits of byte 62) of the whole signature BigInteger.
        for (int i = 0; i < 8; i++) {
            if (signature.testBit(i)) return false;
        }
        return !(signature.testBit(14) || signature.testBit(15));
    }

    private static byte[] to32BytesBe(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        // Copy the LOW 32 bytes of raw into out (right-aligned).
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }

    private static byte[] reverse(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) out[i] = in[in.length - 1 - i];
        return out;
    }

    private record SignedTriple(BigInteger publicKey, byte[] digest, BigInteger signature) {
        SignedTriple {
            assertNotNull(publicKey);
            assertNotNull(digest);
            assertNotNull(signature);
        }
    }

}
