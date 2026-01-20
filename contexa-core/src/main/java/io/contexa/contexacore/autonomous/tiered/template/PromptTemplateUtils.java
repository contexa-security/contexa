package io.contexa.contexacore.autonomous.tiered.template;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;

import java.util.Map;
import java.util.regex.Pattern;


public final class PromptTemplateUtils {

    private PromptTemplateUtils() {
        
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

    
    public static String buildDataQualitySection(SecurityEvent event, String baselineContext) {
        StringBuilder result = new StringBuilder();
        java.util.List<String> criticalMissing = new java.util.ArrayList<>();
        java.util.List<String> criticalPresent = new java.util.ArrayList<>();
        java.util.List<String> highMissing = new java.util.ArrayList<>();

        

        
        boolean hasBaseline = baselineContext != null
            && !baselineContext.startsWith("[NO")
            && !baselineContext.startsWith("[SERVICE")
            && !baselineContext.contains("CRITICAL: NO USER BASELINE")
            && !baselineContext.contains("[NEW_USER]");
        if (hasBaseline) {
            criticalPresent.add("baseline");
        } else {
            criticalMissing.add("baseline");
        }

        
        

        
        if (isValidData(event.getUserId())) {
            criticalPresent.add("userId");
        } else {
            criticalMissing.add("userId");
        }

        
        if (isValidData(event.getSourceIp())) {
            criticalPresent.add("sourceIp");
        } else {
            criticalMissing.add("sourceIp");
        }

        
        if (isValidData(event.getSessionId())) {
            criticalPresent.add("sessionId");
        } else {
            criticalMissing.add("sessionId");
        }

        
        
        java.util.List<String> highPresent = new java.util.ArrayList<>();
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && metadata.containsKey("isNewSession")) {
            highPresent.add("isNewSession");
        } else {
            highMissing.add("isNewSession");
        }
        if (metadata != null && metadata.containsKey("isNewDevice")) {
            highPresent.add("isNewDevice");
        } else {
            highMissing.add("isNewDevice");
        }
        if (metadata != null && metadata.containsKey("recentRequestCount")) {
            highPresent.add("recentRequestCount");
        } else {
            highMissing.add("recentRequestCount");
        }

        
        
        int score = criticalPresent.size() + highPresent.size();
        int maxScore = 7;

        
        result.append(String.format("Decision Data: %d/%d fields available\n", score, maxScore));

        if (!criticalMissing.isEmpty()) {
            result.append(String.format("CRITICAL MISSING: %s\n", String.join(", ", criticalMissing)));
        }
        if (!highMissing.isEmpty()) {
            result.append(String.format("HIGH MISSING: %s\n", String.join(", ", highMissing)));
        }

        
        
        
        if (!hasBaseline) {
            result.append("\n=== ZERO TRUST: NO BASELINE DATA ===\n");
            result.append("- Verification not possible: No historical behavior data to compare\n");
            result.append("- Zero Trust principle: 'Never Trust, Always Verify'\n");
            result.append("- Without baseline, user behavior cannot be validated\n");
        }

        return result.toString();
    }

    
    @Deprecated
    public static String buildDataQualitySection(SecurityEvent event) {
        
        return buildDataQualitySection(event, null);
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
