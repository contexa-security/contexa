package io.contexa.showcase.portal.visitor;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

/**
 * The signed visitor cookie (plan 3.4: a visitor is a signed cookie identifier, never an address). The value is a
 * random identifier and its HMAC; a cookie whose signature does not verify is treated as absent. The database keeps
 * only the SHA-256 of the identifier. The cookie key is derived from the portal's internal signing key with its own
 * label, so the two uses never share a key.
 */
public class VisitorCookies {

    public static final String NAME = "SC_VISITOR";
    static final String LABEL = "showcase-visitor-cookie-v1";
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private final byte[] key;
    private final SecureRandom random = new SecureRandom();

    public VisitorCookies(String signingKeyBase64) {
        if (signingKeyBase64 == null || signingKeyBase64.isBlank()) {
            throw new IllegalStateException("showcase.internal.signing-key is required for the visitor cookie");
        }
        byte[] signingKey = Base64.getDecoder().decode(signingKeyBase64.trim());
        if (signingKey.length < 32) {
            throw new IllegalStateException("showcase.internal.signing-key must be at least 32 bytes");
        }
        this.key = hmac(signingKey, LABEL.getBytes(StandardCharsets.US_ASCII));
    }

    /** A new cookie value: identifier and signature. */
    public String issue() {
        byte[] identifier = new byte[16];
        random.nextBytes(identifier);
        String id = ENCODER.encodeToString(identifier);
        return id + "." + sign(id);
    }

    /** The identifier of a cookie value whose signature verifies. */
    public Optional<String> verify(String value) {
        if (value == null) {
            return Optional.empty();
        }
        int dot = value.indexOf('.');
        if (dot <= 0 || dot == value.length() - 1) {
            return Optional.empty();
        }
        String id = value.substring(0, dot);
        byte[] expected = sign(id).getBytes(StandardCharsets.US_ASCII);
        byte[] actual = value.substring(dot + 1).getBytes(StandardCharsets.US_ASCII);
        try {
            if (DECODER.decode(id).length != 16) {
                return Optional.empty();
            }
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        return MessageDigest.isEqual(expected, actual) ? Optional.of(id) : Optional.empty();
    }

    /** The stored visitor of a request: the hash of its cookie's identifier when the signature verifies. */
    public Optional<String> visitorOf(HttpServletRequest request) {
        Cookie[] all = request.getCookies();
        if (all == null) {
            return Optional.empty();
        }
        for (Cookie cookie : all) {
            if (NAME.equals(cookie.getName())) {
                return verify(cookie.getValue()).map(VisitorCookies::hash);
            }
        }
        return Optional.empty();
    }

    /** What the database stores for a visitor. */
    public static String hash(String identifier) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(identifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private String sign(String id) {
        return ENCODER.encodeToString(hmac(key, id.getBytes(StandardCharsets.US_ASCII)));
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available", e);
        }
    }
}
