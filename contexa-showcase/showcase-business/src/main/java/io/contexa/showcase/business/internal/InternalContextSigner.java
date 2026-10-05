package io.contexa.showcase.business.internal;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

/**
 * HMAC-SHA256 signature over the request line, a timestamp and every internal context value. The same
 * class signs on the portal side and verifies on the workload side, so both always agree on the canonical form.
 */
public final class InternalContextSigner {

    private static final String ALGORITHM = "HmacSHA256";
    private static final int MINIMUM_KEY_BYTES = 32;

    private final byte[] key;

    public InternalContextSigner(String base64Key) {
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalStateException("The showcase internal signing key is not configured");
        }
        this.key = Base64.getDecoder().decode(base64Key.trim());
        if (key.length < MINIMUM_KEY_BYTES) {
            throw new IllegalStateException("The showcase internal signing key must be at least 32 bytes");
        }
    }

    public String sign(String method, String path, long timestampEpochSeconds, InternalContext context) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            byte[] digest = mac.doFinal(canonical(method, path, timestampEpochSeconds, context)
                    .getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is not available", e);
        }
    }

    public boolean verify(String method, String path, long timestampEpochSeconds, InternalContext context,
                          String signature) {
        if (signature == null || signature.isBlank()) {
            return false;
        }
        byte[] expected = sign(method, path, timestampEpochSeconds, context).getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(expected, signature.trim().getBytes(StandardCharsets.US_ASCII));
    }

    static String canonical(String method, String path, long timestampEpochSeconds, InternalContext context) {
        return String.join("\n", List.of(
                nullToEmpty(method),
                nullToEmpty(path),
                Long.toString(timestampEpochSeconds),
                nullToEmpty(context.runId()),
                nullToEmpty(context.requestId()),
                context.observedAt() == null ? "" : context.observedAt().toString(),
                nullToEmpty(context.clientIp()),
                nullToEmpty(context.device()),
                nullToEmpty(context.organization()),
                nullToEmpty(context.tenant())));
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
