package com.dmp.edi.security;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * REST controller that exposes 2FA (TOTP) endpoints.
 *
 * <p>Typical flow:
 * <ol>
 *   <li>Client calls {@code GET /api/2fa/setup?username=&lt;user&gt;} to receive
 *       a QR-code URL and the {@code otpauth://} URI.  The generated secret is
 *       stored server-side, keyed by username.</li>
 *   <li>User scans the QR code with their authenticator app.</li>
 *   <li>Client calls {@code POST /api/2fa/verify} with only the username and the
 *       6-digit code.  The server looks up the stored secret; no secret is ever
 *       sent back to the client after the initial setup response.</li>
 * </ol>
 * </p>
 *
 * <p><strong>Note:</strong> The in-memory secret store used here is intentionally
 * simple.  In a production system the secrets must be persisted in an encrypted
 * column of the user table (or equivalent secure store) so that they survive
 * application restarts.</p>
 */
@RestController
@RequestMapping("/api/2fa")
public class TwoFactorAuthController {

    private static final String ISSUER = "DMP-ETL Platform";
    private static final int QR_SIZE = 200;

    private final TwoFactorAuthService twoFactorAuthService;

    /**
     * Server-side secret store keyed by username.
     *
     * Replace with a proper encrypted persistence layer in production.
     */
    private final ConcurrentHashMap<String, String> pendingSecrets = new ConcurrentHashMap<>();

    public TwoFactorAuthController(TwoFactorAuthService twoFactorAuthService) {
        this.twoFactorAuthService = twoFactorAuthService;
    }

    /**
     * Generates a new TOTP secret for the given user, stores it server-side,
     * and returns the QR-code URL and the {@code otpauth://} URI so the client
     * can render the setup wizard.  The raw secret is included once in this
     * response so the user can enter it manually into their authenticator app
     * if QR scanning is unavailable.
     *
     * @param username the account identifier for the user being enrolled
     * @return JSON with {@code totpUri}, {@code qrCodeUrl}, and {@code secretForDisplay}
     */
    @GetMapping("/setup")
    public ResponseEntity<Map<String, String>> setup(@RequestParam String username) {
        if (username == null || username.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        String secret = twoFactorAuthService.generateSecret();
        pendingSecrets.put(username, secret);
        String totpUri = twoFactorAuthService.buildTotpUri(ISSUER, username, secret);
        return ResponseEntity.ok(Map.of(
                "totpUri", totpUri,
                "qrCodeUrl", "/api/2fa/qrcode?username=" + encodeParam(username),
                "secretForDisplay", secret
        ));
    }

    /**
     * Renders the QR code PNG for the pending TOTP URI of the given user.
     *
     * @param username the account identifier
     * @return PNG image bytes, or 404 if no pending setup was found for the user
     */
    @GetMapping(value = "/qrcode", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> qrCode(@RequestParam String username) {
        String secret = pendingSecrets.get(username);
        if (secret == null) {
            return ResponseEntity.notFound().build();
        }
        String totpUri = twoFactorAuthService.buildTotpUri(ISSUER, username, secret);
        try {
            byte[] png = generateQrCodePng(totpUri, QR_SIZE);
            return ResponseEntity.ok(png);
        } catch (WriterException | IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Verifies a TOTP code using the server-side secret for the given user.
     * The secret is <em>never</em> accepted from the client.
     *
     * <p>Request body: {@code {"username": "...", "code": "123456"} }</p>
     *
     * @param body map containing {@code username} and {@code code}
     * @return {@code {"valid": true}} or {@code {"valid": false}}
     */
    @PostMapping("/verify")
    public ResponseEntity<Map<String, Boolean>> verify(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String code = body.get("code");
        if (username == null || code == null) {
            return ResponseEntity.badRequest().build();
        }
        String secret = pendingSecrets.get(username);
        if (secret == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        boolean valid = twoFactorAuthService.verifyCode(secret, code);
        return ResponseEntity.ok(Map.of("valid", valid));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private byte[] generateQrCodePng(String content, int size) throws WriterException, IOException {
        QRCodeWriter writer = new QRCodeWriter();
        BitMatrix matrix = writer.encode(content, BarcodeFormat.QR_CODE, size, size);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(matrix, "PNG", out);
        return out.toByteArray();
    }

    private String encodeParam(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
