package com.dmp.edi.security;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

/**
 * Service for Time-based One-Time Password (TOTP) two-factor authentication.
 *
 * <p>Implements RFC 6238 (TOTP) and RFC 4226 (HOTP) to generate and verify
 * one-time passwords compatible with standard authenticator apps such as
 * Google Authenticator and Authy.</p>
 */
@Service
public class TwoFactorAuthService {

    private static final String HMAC_ALGORITHM = "HmacSHA1";
    private static final int SECRET_BYTES = 20;
    private static final int CODE_DIGITS = 6;
    private static final int TIME_STEP_SECONDS = 30;
    /** Number of adjacent time windows to accept (handles clock skew). */
    private static final int ALLOWED_WINDOW = 1;

    private static final int[] DIGITS_POWER = {
        1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000
    };

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates a new random Base32-encoded secret for use in TOTP.
     *
     * @return a 20-byte Base32-encoded secret string
     */
    public String generateSecret() {
        byte[] bytes = new byte[SECRET_BYTES];
        secureRandom.nextBytes(bytes);
        return base32Encode(bytes);
    }

    /**
     * Builds a {@code otpauth://} URI that can be embedded in a QR code for
     * easy import into authenticator apps.
     *
     * @param issuer     the application name shown in the authenticator app
     * @param accountName the user's account identifier (e.g. email address)
     * @param secret     the Base32-encoded TOTP secret
     * @return the {@code otpauth://totp/...} URI string
     */
    public String buildTotpUri(String issuer, String accountName, String secret) {
        String label = encode(issuer) + ":" + encode(accountName);
        return "otpauth://totp/" + label
                + "?secret=" + secret
                + "&issuer=" + encode(issuer)
                + "&algorithm=SHA1"
                + "&digits=" + CODE_DIGITS
                + "&period=" + TIME_STEP_SECONDS;
    }

    /**
     * Generates the current TOTP code for the given secret.
     *
     * @param secret the Base32-encoded TOTP secret
     * @return the current 6-digit TOTP code as a zero-padded string
     */
    public String generateCode(String secret) {
        long counter = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;
        return generateHotp(base32Decode(secret), counter);
    }

    /**
     * Verifies whether the provided code is valid for the given secret,
     * accepting codes from adjacent time windows to handle clock skew.
     *
     * @param secret the Base32-encoded TOTP secret
     * @param code   the 6-digit code submitted by the user
     * @return {@code true} if the code is valid, {@code false} otherwise
     */
    public boolean verifyCode(String secret, String code) {
        if (code == null || code.length() != CODE_DIGITS) {
            return false;
        }
        byte[] decodedSecret = base32Decode(secret);
        long currentCounter = Instant.now().getEpochSecond() / TIME_STEP_SECONDS;
        for (int i = -ALLOWED_WINDOW; i <= ALLOWED_WINDOW; i++) {
            if (generateHotp(decodedSecret, currentCounter + i).equals(code)) {
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private String generateHotp(byte[] secret, long counter) {
        byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array();
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            byte[] hash = mac.doFinal(counterBytes);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int otp = binary % DIGITS_POWER[CODE_DIGITS];
            return String.format("%0" + CODE_DIGITS + "d", otp);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Failed to generate HOTP", e);
        }
    }

    // -------------------------------------------------------------------------
    // Base32 helpers (RFC 4648, no padding required by authenticator apps)
    // -------------------------------------------------------------------------

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                sb.append(BASE32_ALPHABET.charAt((buffer >> bitsLeft) & 0x1F));
            }
        }
        if (bitsLeft > 0) {
            sb.append(BASE32_ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return sb.toString();
    }

    private byte[] base32Decode(String data) {
        String upper = data.toUpperCase().replaceAll("[=\\s]", "");
        int outputLength = (upper.length() * 5) / 8;
        byte[] result = new byte[outputLength];
        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;
        for (char c : upper.toCharArray()) {
            int val = BASE32_ALPHABET.indexOf(c);
            if (val < 0) {
                throw new IllegalArgumentException("Invalid Base32 character: " + c);
            }
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                result[index++] = (byte) ((buffer >> bitsLeft) & 0xFF);
            }
        }
        return result;
    }

    private String encode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8)
                .replace("+", "%20");
    }
}
