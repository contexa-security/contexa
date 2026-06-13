package io.contexa.contexacore.verification.runtime;

import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Locale;

public final class OfficialVerificationReplayPathSupport {

    private static final List<String> MANUAL_PATH_PREFIXES = List.of(
            "/admin/api/security-test/",
            "/api/security-test/",
            "/admin/api/enterprise/verification/runtime/probe/",
            "/internal/api/demo-verification/probe/"
    );

    private OfficialVerificationReplayPathSupport() {
    }

    public static ReplayTarget resolveProbeTarget(
            String endpointKey,
            String resourceId,
            String requestPath,
            List<String> allowedEndpointKeys
    ) {
        String normalizedRequestPath = normalizeReplayPath(requestPath);
        if (StringUtils.hasText(normalizedRequestPath)) {
            ReplayTarget parsed = parseProbeTarget(normalizedRequestPath, allowedEndpointKeys);
            String requestedEndpointKey = StringUtils.hasText(endpointKey)
                    ? normalizeEndpointKey(endpointKey, allowedEndpointKeys)
                    : null;
            if (StringUtils.hasText(requestedEndpointKey) && !requestedEndpointKey.equals(parsed.endpointKey())) {
                throw new IllegalArgumentException(
                        "Manual replay endpointKey conflicts with requestPath. Remove the preset endpoint or match the protected request path exactly."
                );
            }
            String requestedResourceId = StringUtils.hasText(resourceId)
                    ? normalizeResourceId(resourceId)
                    : null;
            if (StringUtils.hasText(requestedResourceId) && !requestedResourceId.equals(parsed.resourceId())) {
                throw new IllegalArgumentException(
                        "Manual replay resourceId conflicts with requestPath. Remove the preset resourceId or match the protected request path exactly."
                );
            }
            return parsed;
        }
        return buildTarget(
                normalizeEndpointKey(endpointKey, allowedEndpointKeys),
                normalizeResourceId(resourceId),
                "/internal/api/demo-verification/probe/"
        );
    }

    public static ReplayTarget retargetProbeTarget(
            String endpointKey,
            String resourceId,
            String requestPath,
            List<String> allowedEndpointKeys
    ) {
        String normalizedRequestPath = normalizeReplayPath(requestPath);
        if (StringUtils.hasText(normalizedRequestPath)) {
            ReplayTarget parsed = parseProbeTarget(normalizedRequestPath, allowedEndpointKeys);
            String resolvedEndpointKey = StringUtils.hasText(endpointKey)
                    ? normalizeEndpointKey(endpointKey, allowedEndpointKeys)
                    : parsed.endpointKey();
            String resolvedResourceId = StringUtils.hasText(resourceId)
                    ? normalizeResourceId(resourceId)
                    : parsed.resourceId();
            return buildTarget(resolvedEndpointKey, resolvedResourceId, parsed.pathFamilyPrefix());
        }
        return buildTarget(
                normalizeEndpointKey(endpointKey, allowedEndpointKeys),
                normalizeResourceId(resourceId),
                "/internal/api/demo-verification/probe/"
        );
    }

    public static ReplayTarget parseProbeTarget(String requestPath, List<String> allowedEndpointKeys) {
        String normalizedRequestPath = normalizeReplayPath(requestPath);
        if (!StringUtils.hasText(normalizedRequestPath)) {
            throw new IllegalArgumentException("Replay path must not be blank.");
        }
        String matchedPrefix = MANUAL_PATH_PREFIXES.stream()
                .filter(normalizedRequestPath::startsWith)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Official verification accepts replay paths only under /admin/api/security-test/**, /api/security-test/**, /admin/api/enterprise/verification/runtime/probe/**, or /internal/api/demo-verification/probe/**"
                ));
        String remainder = normalizedRequestPath.substring(matchedPrefix.length());
        String[] segments = remainder.split("/", 2);
        if (segments.length != 2 || !StringUtils.hasText(segments[1])) {
            throw new IllegalArgumentException(
                    "Replay path must follow /admin/api/security-test/{endpointKey}/{resourceId}, /admin/api/enterprise/verification/runtime/probe/{endpointKey}/{resourceId}, or /internal/api/demo-verification/probe/{endpointKey}/{resourceId}"
            );
        }
        String parsedEndpointKey = StringUtils.hasText(segments[0]) ? segments[0].trim().toLowerCase(Locale.ROOT) : null;
        if (!allowedEndpointKeys.contains(parsedEndpointKey)) {
            throw new IllegalArgumentException("Unsupported verification replay endpointKey: " + segments[0]);
        }
        String resolvedResourceId = normalizeResourceId(segments[1]);
        return buildTarget(parsedEndpointKey, resolvedResourceId, matchedPrefix);
    }

    public static String normalizeReplayPath(String requestPath) {
        if (!StringUtils.hasText(requestPath)) {
            return null;
        }
        String normalized = requestPath.trim();
        int schemeIndex = normalized.indexOf("://");
        if (schemeIndex >= 0) {
            int pathStart = normalized.indexOf('/', schemeIndex + 3);
            normalized = pathStart >= 0 ? normalized.substring(pathStart) : "/";
        }
        int queryStart = normalized.indexOf('?');
        if (queryStart >= 0) {
            normalized = normalized.substring(0, queryStart);
        }
        int fragmentStart = normalized.indexOf('#');
        if (fragmentStart >= 0) {
            normalized = normalized.substring(0, fragmentStart);
        }
        return normalized;
    }

    public static String normalizeResourceId(String resourceId) {
        String normalized = StringUtils.hasText(resourceId) ? resourceId.trim() : "resource-001";
        normalized = normalized.replaceAll("[^A-Za-z0-9._-]", "-");
        return normalized.isBlank() ? "resource-001" : normalized;
    }

    public static String normalizeEndpointKey(String endpointKey, List<String> allowedEndpointKeys) {
        String normalized = StringUtils.hasText(endpointKey) ? endpointKey.trim().toLowerCase(Locale.ROOT) : null;
        if (normalized != null && allowedEndpointKeys.contains(normalized)) {
            return normalized;
        }
        if (allowedEndpointKeys.contains("normal")) {
            return "normal";
        }
        if (!allowedEndpointKeys.isEmpty()) {
            return allowedEndpointKeys.get(0);
        }
        throw new IllegalArgumentException("Official verification endpoint set must not be empty.");
    }

    private static ReplayTarget buildTarget(String endpointKey, String resourceId, String familyPrefix) {
        return new ReplayTarget(
                endpointKey,
                resourceId,
                familyPrefix + endpointKey + "/" + resourceId,
                familyPrefix
        );
    }

    public record ReplayTarget(
            String endpointKey,
            String resourceId,
            String requestPath,
            String pathFamilyPrefix
    ) {
    }
}