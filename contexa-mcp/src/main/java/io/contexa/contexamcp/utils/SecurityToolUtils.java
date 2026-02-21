package io.contexa.contexamcp.utils;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@UtilityClass
public class SecurityToolUtils {

    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$"
    );

    private static final Pattern IPV6_PATTERN = Pattern.compile(
        "^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|" +
        "([0-9a-fA-F]{1,4}:){1,7}:|" +
        "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|" +
        "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|" +
        "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|" +
        "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|" +
        "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|" +
        "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|" +
        ":((:[0-9a-fA-F]{1,4}){1,7}|:))$"
    );

    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
        "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    );

    private static final Pattern PORT_PATTERN = Pattern.compile(
        "^([1-9]|[1-9]\\d{1,3}|[1-5]\\d{4}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])$"
    );
    
    private static final DateTimeFormatter AUDIT_DATE_FORMAT = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    public static void auditLog(String toolName, String action, String user, Object... parameters) {
        Map<String, Object> auditEntry = new HashMap<>();
        auditEntry.put("timestamp", LocalDateTime.now().format(AUDIT_DATE_FORMAT));
        auditEntry.put("tool", toolName);
        auditEntry.put("action", action);
        auditEntry.put("user", user != null ? user : "SYSTEM");
        
        if (parameters != null && parameters.length > 0) {
            String params = Arrays.stream(parameters)
                .map(p -> p != null ? sanitizeForLog(p.toString()) : "null")
                .collect(Collectors.joining(", "));
            auditEntry.put("parameters", params);
        }

        // TODO: Integrate with persistent audit store (e.g., AuditLogService)
        log.error("AUDIT: tool={}, action={}, user={}, params={}",
                toolName, action, auditEntry.get("user"), auditEntry.get("parameters"));
    }

    public static void auditLog(String toolName, String message) {
        auditLog(toolName, message, null);
    }

    public static boolean isValidIpv4Address(String ip) {
        if (!StringUtils.hasText(ip)) {
            return false;
        }
        return IPV4_PATTERN.matcher(ip.trim()).matches();
    }

    public static boolean isValidIpv6Address(String ip) {
        if (!StringUtils.hasText(ip)) {
            return false;
        }
        return IPV6_PATTERN.matcher(ip.trim()).matches();
    }

    public static boolean isValidIpAddress(String ip) {
        return isValidIpv4Address(ip) || isValidIpv6Address(ip);
    }

    public static boolean isInternalIpAddress(String ip) {
        if (!isValidIpv4Address(ip)) {
            return false;
        }
        
        String trimmedIp = ip.trim();

        if (trimmedIp.startsWith("10.")) {
            return true;
        }

        if (trimmedIp.startsWith("172.")) {
            String[] parts = trimmedIp.split("\\.");
            if (parts.length >= 2) {
                try {
                    int secondOctet = Integer.parseInt(parts[1]);
                    return secondOctet >= 16 && secondOctet <= 31;
                } catch (NumberFormatException e) {
                    return false;
                }
            }
        }

        if (trimmedIp.startsWith("192.168.")) {
            return true;
        }

        if (trimmedIp.startsWith("127.")) {
            return true;
        }

        if (trimmedIp.startsWith("169.254.")) {
            return true;
        }
        
        return false;
    }

    public static boolean isValidDomain(String domain) {
        if (!StringUtils.hasText(domain)) {
            return false;
        }

        if (domain.length() > 253) {
            return false;
        }
        
        return DOMAIN_PATTERN.matcher(domain.trim()).matches();
    }

    public static boolean isValidPort(int port) {
        return port >= 1 && port <= 65535;
    }

    public static boolean isValidPort(String portStr) {
        if (!StringUtils.hasText(portStr)) {
            return false;
        }
        return PORT_PATTERN.matcher(portStr.trim()).matches();
    }

    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }

        String sanitized = input.length() > 500 
            ? input.substring(0, 497) + "..." 
            : input;

        sanitized = sanitized
            .replaceAll("[\r\n]", " ")
            .replaceAll("\\p{Cntrl}", "")
            .replaceAll("password=\\S+", "password=***")
            .replaceAll("token=\\S+", "token=***")
            .replaceAll("apikey=\\S+", "apikey=***")
            .replaceAll("secret=\\S+", "secret=***");
        
        return sanitized;
    }

    public static String calculateThreatLevel(int score) {
        if (score >= 80) return "CRITICAL";
        if (score >= 60) return "HIGH";
        if (score >= 40) return "MEDIUM";
        if (score >= 20) return "LOW";
        return "MINIMAL";
    }

    public static void logExecutionTime(String toolName, String operation, long startTime) {
        long duration = System.currentTimeMillis() - startTime;
        
        if (duration > 5000) {
            log.error("SLOW OPERATION: Tool={}, Operation={}, Duration={}ms",
                    toolName, operation, duration);
        } else {
            log.error("Tool={}, Operation={}, Duration={}ms", toolName, operation, duration);
        }
    }

    public static void requireNonEmpty(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(fieldName + " is required and cannot be empty");
        }
    }

    public static void requireNonNull(Object value, String fieldName) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " is required and cannot be null");
        }
    }

    public static void requireInRange(int value, int min, int max, String fieldName) {
        if (value < min || value > max) {
            throw new IllegalArgumentException(
                String.format("%s must be between %d and %d, but was %d", 
                             fieldName, min, max, value)
            );
        }
    }

    public static void recordMetric(String toolName, String metricName, Object value) {
        // TODO: Integrate with metrics system (e.g., Micrometer)
        log.error("METRIC: tool={}, metric={}, value={}", toolName, metricName, value);
    }

}