package io.contexa.contexacore.autonomous.tiered.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.Map;
import java.util.regex.Pattern;

public final class PromptTemplateUtils {

    private static final ThreadLocal<Boolean> TRUNCATION_DISABLED =
            ThreadLocal.withInitial(() -> Boolean.FALSE);

    private PromptTemplateUtils() {
        
    }

    public static boolean isTruncationDisabled() {
        return Boolean.TRUE.equals(TRUNCATION_DISABLED.get());
    }

    public static TruncationScope disableTruncationForCurrentThread(boolean disabled) {
        Boolean previous = TRUNCATION_DISABLED.get();
        TRUNCATION_DISABLED.set(disabled);
        return new TruncationScope(previous);
    }

    public static boolean isValidData(String value) {
        return value != null && !value.isEmpty() && !value.equalsIgnoreCase("unknown");
    }

    public static String getStringFromMetadata(Map<String, Object> metadata, String key) {
        if (metadata == null) {
            return null;
        }
        Object value = metadata.get(key);
        if (value == null) {
            return null;
        }
        String strValue = value.toString();
        return strValue.isEmpty() ? null : strValue;
    }

    public static String extractSimpleClassName(String fullClassName) {
        if (fullClassName == null || fullClassName.isEmpty()) {
            return null;
        }
        int lastDot = fullClassName.lastIndexOf('.');
        if (lastDot >= 0 && lastDot < fullClassName.length() - 1) {
            return fullClassName.substring(lastDot + 1);
        }
        return fullClassName;
    }

    public static int calculateDataQuality(SecurityEvent event) {
        int score = 0;

        if (event.getSeverity() != null) score++;
        if (isValidData(event.getUserId())) score++;
        if (isValidData(event.getSourceIp())) score++;
        if (isValidData(event.getUserAgent())) score++;

        if (isValidData(event.getSessionId())) score++;
        if (event.getTimestamp() != null) score++;

        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && !metadata.isEmpty()) {
            if (metadata.containsKey("methodClass")) score++;
        }

        return Math.min(10, score);
    }

    public static String buildNetworkSection(SecurityEvent event) {
        StringBuilder network = new StringBuilder();

        if (isValidData(event.getSourceIp())) {
            network.append("IP: ").append(event.getSourceIp()).append("\n");
        }

        if (isValidData(event.getUserAgent())) {
            String ua = event.getUserAgent();
            if (ua.length() > 150) {
                ua = ua.substring(0, 147) + "...";
            }
            network.append("UserAgent: ").append(ua).append("\n");
        }

        return network.toString().trim();
    }

    public static String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        if (isTruncationDisabled()) {
            return value;
        }
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength - 3) + "...";
    }

    public static String truncateOrNA(String value, int maxLength) {
        if (value == null || value.isEmpty()) {
            return "N/A";
        }
        return truncate(value, maxLength);
    }

    public static String sanitizeUserInput(String input) {
        if (input == null) {
            return null;
        }
        return input
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", " ")
            .replace("\r", " ")
            .replace("`", "'")
            .replace("{", "(")
            .replace("}", ")");
    }

    public static String sanitizeAndTruncate(String input, int maxLength) {
        String sanitized = sanitizeUserInput(input);
        return truncate(sanitized, maxLength);
    }

    public static final class TruncationScope implements AutoCloseable {

        private final Boolean previous;
        private boolean closed;

        private TruncationScope(Boolean previous) {
            this.previous = previous;
        }

        @Override
        public void close() {
            if (closed) {
                return;
            }
            if (Boolean.TRUE.equals(previous)) {
                TRUNCATION_DISABLED.set(Boolean.TRUE);
            } else {
                TRUNCATION_DISABLED.remove();
            }
            closed = true;
        }
    }

    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    private static final Pattern IPV6_PATTERN = Pattern.compile(
        "^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|" +
        "([0-9a-fA-F]{1,4}:){1,7}:|" +
        "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|" +
        "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|" +
        "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|" +
        "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|" +
        "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|" +
        "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|" +
        ":((:[0-9a-fA-F]{1,4}){1,7}|:)|" +
        "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|" +
        "::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|" +
        "([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$");

    public static boolean isValidIpFormat(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        return IPV4_PATTERN.matcher(ip).matches() || IPV6_PATTERN.matcher(ip).matches();
    }

    public static void appendIpWithValidation(StringBuilder sb, String ip) {
        if (ip == null || ip.isEmpty()) {
            sb.append("IP: NOT_PROVIDED [CRITICAL]\n");
        } else if (!isValidIpFormat(ip)) {
            sb.append("IP: ").append(sanitizeUserInput(ip)).append(" [INVALID_FORMAT]\n");
        } else {
            sb.append("IP: ").append(sanitizeUserInput(ip)).append("\n");
        }
    }
}
