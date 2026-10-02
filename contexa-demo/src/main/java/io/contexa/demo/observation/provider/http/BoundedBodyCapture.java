package io.contexa.demo.observation.provider.http;

import io.contexa.demo.observation.provider.dto.ObservedProviderBody;
import io.contexa.demo.observation.provider.service.ProviderBodySanitizer;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** Keeps a bounded copy while hashing only bytes actually passed through this boundary. */
public final class BoundedBodyCapture {

    private static final int LIMIT = 65536;
    private final ByteArrayOutputStream retained = new ByteArrayOutputStream();
    private final MessageDigest digest;
    private long observed;
    private boolean complete;
    private boolean skipped;

    public BoundedBodyCapture() {
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is required", unavailable);
        }
    }

    public void accept(byte[] bytes, int offset, int length) {
        digest.update(bytes, offset, length);
        observed += length;
        int remaining = LIMIT - retained.size();
        if (remaining > 0) {
            retained.write(bytes, offset, Math.min(remaining, length));
        }
    }

    public void complete() {
        complete = true;
    }

    public void skipped() {
        skipped = true;
    }

    public ObservedProviderBody finish(ProviderBodySanitizer sanitizer, long expectedBytes) {
        boolean all = !skipped && (complete || (expectedBytes >= 0 && observed == expectedBytes));
        String hash = HexFormat.of().formatHex(digest.digest());
        String body = !skipped && observed <= LIMIT ? sanitizer.sanitize(retained.toByteArray()) : null;
        String state;
        if (body != null) {
            state = all ? "SANITIZED_JSON" : "SANITIZED_JSON_END_UNCONFIRMED";
        } else {
            state = !all ? "INCOMPLETE" : observed > LIMIT ? "OMITTED_LIMIT" : "OMITTED_NON_JSON";
        }
        String basis = skipped ? "SKIPPED_OR_UNTRACKED_RESET" : complete ? "END_OF_STREAM"
                : all ? "CONTENT_LENGTH" : "CONSUMED_PREFIX_ONLY";
        return new ObservedProviderBody(state, observed, all, hash, body, basis);
    }
}
