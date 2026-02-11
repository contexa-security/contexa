package io.contexa.contexacore.autonomous.tiered.util;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import lombok.extern.slf4j.Slf4j;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

@Slf4j
public class SecurityEventEnricher {

    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/=]{4,}$");
    private static final Pattern URL_ENCODED_PATTERN = Pattern.compile(".*%[0-9A-Fa-f]{2}.*");
    public static final String TARGET_RESOURCE = "targetResource";
    public static final String REQUEST_PAYLOAD = "requestPayload";
    public static final String PATTERN_SCORE = "patternScore";
    public static final String RISK_INDICATORS = "riskIndicators";

    public Optional<String> getTargetResource(SecurityEvent event) {

        Optional<String> target = getMetadataValue(event, TARGET_RESOURCE, String.class);
        if (target.isPresent()) {
            return target;
        }

        Optional<String> requestUri = getMetadataValue(event, "requestUri", String.class);
        if (requestUri.isPresent()) {
            return requestUri;
        }

        return getMetadataValue(event, "fullPath", String.class);
    }

    public Optional<Object> getRequestPayload(SecurityEvent event) {
        return getMetadataValue(event, REQUEST_PAYLOAD, Object.class);
    }

    public Optional<String> getDecodedPayload(SecurityEvent event) {
        return getRequestPayload(event)
                .map(payload -> {
                    String payloadStr = payload.toString();
                    return decodePayload(payloadStr);
                });
    }

    private String decodePayload(String payload) {
        if (payload == null || payload.isEmpty()) {
            return payload;
        }

        String decoded = payload;

        if (URL_ENCODED_PATTERN.matcher(payload).matches()) {
            try {
                decoded = URLDecoder.decode(payload, StandardCharsets.UTF_8);
            } catch (Exception e) {
                log.warn("Failed to decode URL-encoded payload: {}", truncateForLog(payload), e);
            }
        }

        if (isLikelyBase64(decoded)) {
            try {
                byte[] decodedBytes = Base64.getDecoder().decode(decoded);
                String base64Decoded = new String(decodedBytes, StandardCharsets.UTF_8);

                if (isPrintable(base64Decoded)) {
                    decoded = base64Decoded;
                }
            } catch (Exception e) {
            }
        }

        return decoded;
    }

    private boolean isLikelyBase64(String str) {
        if (str == null || str.length() < 8) {
            return false;
        }

        return str.length() % 4 == 0 && BASE64_PATTERN.matcher(str).matches();
    }

    private boolean isPrintable(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }

        long printableCount = str.chars()
                .filter(c -> c >= 32 && c < 127)
                .count();
        return (double) printableCount / str.length() >= 0.8;
    }

    private String truncateForLog(String str) {
        if (str == null) return "null";
        if (str.length() <= 50) return str;
        return str.substring(0, 47) + "...";
    }

    private <T> Optional<T> getMetadataValue(SecurityEvent event, String key, Class<T> type) {
        if (event.getMetadata() == null || !event.getMetadata().containsKey(key)) {
            return Optional.empty();
        }

        Object value = event.getMetadata().get(key);
        if (value == null) {
            return Optional.empty();
        }

        if (type.isInstance(value)) {
            return Optional.of((T) value);
        }

        if (Number.class.isAssignableFrom(type) && value instanceof Number numValue) {
            try {
                Object converted = convertNumber(numValue, type);
                if (converted != null) {
                    return Optional.of((T) converted);
                }
            } catch (Exception e) {
                log.warn("[SecurityEventEnricher] Failed to convert number value for key '{}': {}", key, e.getMessage());
            }
        }

        if (Number.class.isAssignableFrom(type) && value instanceof String) {
            try {
                Object converted = parseStringToNumber((String) value, type);
                if (converted != null) {
                    return Optional.of((T) converted);
                }
            } catch (Exception e) {
                log.warn("[SecurityEventEnricher] Failed to parse string value for key '{}': {}", key, e.getMessage());
            }
        }

        if (type == String.class) {
            return Optional.of((T) value.toString());
        }

        log.warn("[SecurityEventEnricher] Type mismatch for key '{}': expected {}, got {}",
                key, type.getSimpleName(), value.getClass().getSimpleName());
        return Optional.empty();
    }

    private Object convertNumber(Number value, Class<?> targetType) {
        if (targetType == Integer.class || targetType == int.class) {
            return value.intValue();
        } else if (targetType == Long.class || targetType == long.class) {
            return value.longValue();
        } else if (targetType == Double.class || targetType == double.class) {
            return value.doubleValue();
        } else if (targetType == Float.class || targetType == float.class) {
            return value.floatValue();
        } else if (targetType == Short.class || targetType == short.class) {
            return value.shortValue();
        } else if (targetType == Byte.class || targetType == byte.class) {
            return value.byteValue();
        }
        return null;
    }

    private Object parseStringToNumber(String value, Class<?> targetType) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        String trimmed = value.trim();
        if (targetType == Integer.class || targetType == int.class) {
            return Integer.parseInt(trimmed);
        } else if (targetType == Long.class || targetType == long.class) {
            return Long.parseLong(trimmed);
        } else if (targetType == Double.class || targetType == double.class) {
            return Double.parseDouble(trimmed);
        } else if (targetType == Float.class || targetType == float.class) {
            return Float.parseFloat(trimmed);
        }
        return null;
    }

    public static String extractOSFromUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }

        if (userAgent.contains("Android")) {
            return "Android";
        }
        if (userAgent.contains("iPhone") || userAgent.contains("iPad")
                || userAgent.contains("iPod") || userAgent.contains("iOS")) {
            return "iOS";
        }

        if (userAgent.contains("Windows NT") || userAgent.contains("Windows")) {
            return "Windows";
        }
        if (userAgent.contains("Mac OS X") || userAgent.contains("Macintosh")) {
            return "Mac";
        }
        if (userAgent.contains("CrOS")) {
            return "ChromeOS";
        }
        if (userAgent.contains("Linux")) {
            return "Linux";
        }

        if (userAgent.contains("Mobile") || userAgent.contains("Tablet")) {
            return "Mobile";
        }

        return "Desktop";
    }

    public static String extractBrowserSignature(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }

        if (userAgent.contains("Edg/")) {
            return extractBrowserVersion(userAgent, "Edg/", "Edge");
        }

        if (userAgent.contains("Chrome/") && !userAgent.contains("Edg/")) {
            return extractBrowserVersion(userAgent, "Chrome/", "Chrome");
        }

        if (userAgent.contains("Firefox/")) {
            return extractBrowserVersion(userAgent, "Firefox/", "Firefox");
        }

        if (userAgent.contains("Safari/") && userAgent.contains("Version/")) {
            return extractBrowserVersion(userAgent, "Version/", "Safari");
        }

        if (userAgent.contains("OPR/")) {
            return extractBrowserVersion(userAgent, "OPR/", "Opera");
        }

        return null;
    }

    private static String extractBrowserVersion(String userAgent, String prefix, String browserName) {
        int idx = userAgent.indexOf(prefix);
        if (idx == -1) return null;

        int start = idx + prefix.length();
        if (start >= userAgent.length()) return null;

        int end = start;
        while (end < userAgent.length()) {
            char c = userAgent.charAt(end);
            if (c == '.' || c == ' ' || !Character.isDigit(c)) {
                break;
            }
            end++;
        }

        if (end == start) return null;

        String version = userAgent.substring(start, end);
        return browserName + "/" + version;
    }

    public static String normalizeIP(String ip) {
        if (ip == null || ip.isEmpty()) {
            return ip;
        }

        String trimmed = ip.trim().toLowerCase();

        if (trimmed.equals("loopback") ||
                trimmed.equals("::1") ||
                trimmed.equals("0:0:0:0:0:0:0:1") ||
                trimmed.equals("127.0.0.1") ||
                trimmed.equals("localhost")) {
            return "loopback";
        }

        return ip;
    }
}