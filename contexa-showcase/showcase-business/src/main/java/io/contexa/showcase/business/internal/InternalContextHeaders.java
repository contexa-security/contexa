package io.contexa.showcase.business.internal;

import java.util.List;

/**
 * Headers the portal orchestrator sends to the workloads. They carry the run's synthetic context and are
 * honoured only when the HMAC signature over all of them verifies (see {@link InternalContextSigner}).
 */
public final class InternalContextHeaders {

    public static final String RUN = "X-Showcase-Run";
    public static final String REQUEST_ID = "X-Showcase-Request-Id";
    public static final String OBSERVED_AT = "X-Showcase-Observed-At";
    public static final String CLIENT_IP = "X-Showcase-Client-Ip";
    public static final String DEVICE = "X-Showcase-Device";
    public static final String ORGANIZATION = "X-Showcase-Org";
    public static final String TENANT = "X-Showcase-Tenant";
    public static final String TIMESTAMP = "X-Showcase-Timestamp";
    public static final String SIGNATURE = "X-Showcase-Signature";

    /** Client supplied headers that the engine would otherwise trust; they are hidden from every workload. */
    public static final List<String> UNTRUSTED_CLIENT_HEADERS = List.of(
            "X-Request-ID", "X-Forwarded-For", "X-Real-IP", "Forwarded");

    private InternalContextHeaders() {
    }
}
