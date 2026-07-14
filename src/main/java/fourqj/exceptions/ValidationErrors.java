package fourqj.exceptions;

import java.math.BigInteger;

import fourqj.constants.Key;
import fourqj.constants.Params;
import fourqj.utils.CryptoUtils;


public class ValidationErrors {
    /**
     * Returns {@code true} if the signature's scalar component {@code S} is non-canonical, i.e.
     * {@code S >= curve_order r}. In the SchnorrQ encoding used here, the 64-byte signature is
     * (R || S) where R and S are 32-byte little-endian values; the low 256 bits of the signature
     * BigInteger correspond to S in reversed (little-endian) byte order.
     * <p>
     * The previous implementation only enforced {@code S < 2^246}, but the curve order
     * {@code r < 2^246}, leaving the malleability gap {@code [r, 2^246)} accepted: the twin
     * {@code S' = S + r} then verifies for the same message with a different transaction hash,
     * enabling double-execution. See qubic/core commit 05f73489.
     */
    public static boolean isSignatureSizeTooLarge(BigInteger signature) {
        // Extract S as a natural (big-endian) BigInteger from the little-endian low 32 bytes
        // and compare strictly against the curve order.
        final BigInteger s = CryptoUtils.extractSignatureTopBytesReverse(signature);
        return s.compareTo(Params.CURVE_ORDER) >= 0;
   }

    public static void publicKeyError() throws InvalidArgumentException {
        throw new InvalidArgumentException(String.format(
                "Invalid argument: Bit %d is not set to zero in both the public key.",
                Key.PUB_TEST_BIT
        ));
    }

    public static void signatureError() throws InvalidArgumentException {
        throw new InvalidArgumentException(String.format(
                "Invalid argument: Bit %d is not set to zero in both the signature.",
                Key.SIG_TEST_BIT
        ));
    }

    public static void signatureSizeError() throws InvalidArgumentException {
        throw new InvalidArgumentException(
                "Invalid argument: Signature scalar S is non-canonical (S >= curve order)."
        );
    }
}
