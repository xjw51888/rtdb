package com.dmp.edi.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TwoFactorAuthServiceTest {

    private TwoFactorAuthService service;

    @BeforeEach
    void setUp() {
        service = new TwoFactorAuthService();
    }

    // -------------------------------------------------------------------------
    // generateSecret
    // -------------------------------------------------------------------------

    @Test
    void generateSecret_returnsNonEmptyString() {
        String secret = service.generateSecret();
        assertNotNull(secret);
        assertFalse(secret.isEmpty());
    }

    @Test
    void generateSecret_returnsValidBase32() {
        String secret = service.generateSecret();
        // Base32 alphabet: A-Z and 2-7 only
        assertTrue(secret.matches("[A-Z2-7]+"),
                "Secret must contain only Base32 characters, got: " + secret);
    }

    @Test
    void generateSecret_differentEachCall() {
        String s1 = service.generateSecret();
        String s2 = service.generateSecret();
        assertNotEquals(s1, s2, "Two generated secrets should differ");
    }

    // -------------------------------------------------------------------------
    // buildTotpUri
    // -------------------------------------------------------------------------

    @Test
    void buildTotpUri_containsRequiredParts() {
        String secret = service.generateSecret();
        String uri = service.buildTotpUri("MyApp", "user@example.com", secret);
        assertTrue(uri.startsWith("otpauth://totp/"), "URI must start with otpauth://totp/");
        assertTrue(uri.contains("secret=" + secret), "URI must contain the secret");
        assertTrue(uri.contains("issuer=MyApp"), "URI must contain the issuer");
        assertTrue(uri.contains("digits=6"), "URI must specify 6 digits");
        assertTrue(uri.contains("period=30"), "URI must specify 30-second period");
    }

    @Test
    void buildTotpUri_encodesSpecialCharactersInAccount() {
        String secret = service.generateSecret();
        String uri = service.buildTotpUri("My App", "user name@example.com", secret);
        assertFalse(uri.contains(" "), "Spaces must be URL-encoded");
    }

    // -------------------------------------------------------------------------
    // generateCode + verifyCode round-trip
    // -------------------------------------------------------------------------

    @Test
    void verifyCode_acceptsCurrentlyGeneratedCode() {
        String secret = service.generateSecret();
        String code = service.generateCode(secret);
        assertTrue(service.verifyCode(secret, code),
                "A freshly generated code must be valid");
    }

    @Test
    void verifyCode_rejectsWrongCode() {
        String secret = service.generateSecret();
        String code = service.generateCode(secret);
        // Flip the last digit
        String wrong = code.substring(0, 5) + ((code.charAt(5) - '0' + 1) % 10);
        assertFalse(service.verifyCode(secret, wrong),
                "A modified code must be rejected");
    }

    @Test
    void verifyCode_rejectsNullCode() {
        String secret = service.generateSecret();
        assertFalse(service.verifyCode(secret, null));
    }

    @Test
    void verifyCode_rejectsEmptyCode() {
        String secret = service.generateSecret();
        assertFalse(service.verifyCode(secret, ""));
    }

    @Test
    void verifyCode_rejectsTooShortCode() {
        String secret = service.generateSecret();
        assertFalse(service.verifyCode(secret, "12345"));
    }

    @Test
    void verifyCode_rejectsTooLongCode() {
        String secret = service.generateSecret();
        assertFalse(service.verifyCode(secret, "1234567"));
    }

    // -------------------------------------------------------------------------
    // generateCode format
    // -------------------------------------------------------------------------

    @Test
    void generateCode_returnsSixDigits() {
        String secret = service.generateSecret();
        String code = service.generateCode(secret);
        assertNotNull(code);
        assertEquals(6, code.length(), "Code must be exactly 6 characters");
        assertTrue(code.matches("\\d{6}"), "Code must consist of digits only");
    }

    @Test
    void generateCode_deterministicForSameSecretAndTime() {
        String secret = service.generateSecret();
        // Two consecutive calls within the same 30-second window must match
        String code1 = service.generateCode(secret);
        String code2 = service.generateCode(secret);
        assertEquals(code1, code2, "Codes generated in the same time window must be equal");
    }
}
