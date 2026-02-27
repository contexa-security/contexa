package io.contexa.contexamcp.utils;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@UtilityClass
public class SecurityToolUtils {

    private static final String IPV4_REGEX =
        "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$";

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

    public static boolean isValidIpv4Address(String ip) {
        if (!StringUtils.hasText(ip)) {
            return false;
        }
        return ip.trim().matches(IPV4_REGEX);
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

    private static String sanitizeForLog(String input) {
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

    public static void recordMetric(String toolName, String metricName, Object value) {
        // TODO: Integrate with metrics system (e.g., Micrometer)
        log.error("METRIC: tool={}, metric={}, value={}", toolName, metricName, value);
    }

}
