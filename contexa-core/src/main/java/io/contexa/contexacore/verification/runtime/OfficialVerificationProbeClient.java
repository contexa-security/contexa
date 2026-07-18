package io.contexa.contexacore.verification.runtime;

import java.time.Duration;
import java.util.Map;

/**
 * Transport-neutral outbound port used by official verification probes.
 */
@FunctionalInterface
public interface OfficialVerificationProbeClient {

    Map<String, Object> get(
            String baseUrl,
            String requestPath,
            Map<String, String> headers,
            Duration timeout);
}