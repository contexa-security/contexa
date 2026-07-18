package io.contexa.contexacore.verification.runtime;

import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/** Immutable transport-neutral input for official verification execution. */
public record OfficialVerificationExecutionRequest(
        Map<String, String> headers,
        Map<String, Object> attributes,
        String scheme,
        String serverName,
        int serverPort,
        String operatorId,
        VerificationFaultScenario faultScenario
) {

    public OfficialVerificationExecutionRequest {
        headers = normalizeHeaders(headers);
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
        scheme = hasText(scheme) ? scheme.trim() : "http";
        serverName = hasText(serverName) ? serverName.trim() : "localhost";
        serverPort = serverPort > 0 ? serverPort : defaultPort(scheme);
        operatorId = hasText(operatorId) ? operatorId.trim() : "system";
    }

    public static OfficialVerificationExecutionRequest empty() {
        return new OfficialVerificationExecutionRequest(
                Map.of(), Map.of(), "http", "localhost", 80, "system", null);
    }

    public String getHeader(String name) {
        return name == null ? null : headers.get(name.toLowerCase(Locale.ROOT));
    }

    public Enumeration<String> getHeaderNames() {
        return Collections.enumeration(headers.keySet());
    }

    public Object getAttribute(String name) {
        return name == null ? null : attributes.get(name);
    }

    public Enumeration<String> getAttributeNames() {
        return Collections.enumeration(attributes.keySet());
    }

    public String getScheme() {
        return scheme;
    }

    public String getServerName() {
        return serverName;
    }

    public int getServerPort() {
        return serverPort;
    }

    public Optional<VerificationFaultScenario> fault() {
        return Optional.ofNullable(faultScenario);
    }

    public OfficialVerificationExecutionRequest withAttribute(String name, Object value) {
        if (!hasText(name)) {
            return this;
        }
        Map<String, Object> merged = new LinkedHashMap<>(attributes);
        if (value == null) {
            merged.remove(name);
        }
        else {
            merged.put(name, value);
        }
        return new OfficialVerificationExecutionRequest(
                headers, merged, scheme, serverName, serverPort, operatorId, faultScenario);
    }
    public OfficialVerificationExecutionRequest withAttributes(Map<String, ?> additions) {
        if (additions == null || additions.isEmpty()) {
            return this;
        }
        Map<String, Object> merged = new LinkedHashMap<>(attributes);
        additions.forEach((key, value) -> {
            if (key != null && value != null) {
                merged.put(key, value);
            }
        });
        return new OfficialVerificationExecutionRequest(
                headers, merged, scheme, serverName, serverPort, operatorId, faultScenario);
    }

    private static Map<String, String> normalizeHeaders(Map<String, String> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }
        Map<String, String> normalized = new LinkedHashMap<>();
        source.forEach((name, value) -> {
            if (hasText(name) && hasText(value)) {
                normalized.put(name.trim().toLowerCase(Locale.ROOT), value.trim());
            }
        });
        return Map.copyOf(normalized);
    }

    private static int defaultPort(String scheme) {
        return "https".equalsIgnoreCase(scheme) ? 443 : 80;
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}