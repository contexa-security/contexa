package io.contexa.contexacore.verification.runtime;

import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Transport-neutral header values for an official verification probe.
 */
public final class OfficialVerificationProbeHeaders {

    public static final String AUTHORIZATION = "Authorization";
    public static final String COOKIE = "Cookie";
    public static final String USER_AGENT = "User-Agent";
    public static final String ACCEPT = "Accept";

    private final Map<String, String> values = new LinkedHashMap<>();

    public void set(String name, String value) {
        if (StringUtils.hasText(name) && StringUtils.hasText(value)) {
            values.put(name.trim(), value.trim());
        }
    }

    public Map<String, String> asMap() {
        return Map.copyOf(values);
    }
}