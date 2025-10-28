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

/**
 * Security Tool Utilities
 * 
 * SOAR 보안 도구들의 공통 기능을 제공하는 유틸리티 클래스
 * SOLID 원칙에 따라 단일 책임을 가지며, 정적 메서드로 구성
 * 
 * 주요 기능:
 * - 감사 로깅
 * - IP 주소 검증 및 분류
 * - 보안 이벤트 추적
 * - 입력 검증
 * - 메트릭 수집
 */
@Slf4j
@UtilityClass
public class SecurityToolUtils {
    
    // IP 주소 검증 정규식 (IPv4)
    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$"
    );
    
    // IPv6 주소 검증 정규식 (단순화된 버전)
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
    
    // 도메인 이름 검증 정규식
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
        "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    );
    
    // 포트 번호 검증 정규식
    private static final Pattern PORT_PATTERN = Pattern.compile(
        "^([1-9]|[1-9]\\d{1,3}|[1-5]\\d{4}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])$"
    );
    
    private static final DateTimeFormatter AUDIT_DATE_FORMAT = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    
    /**
     * 감사 로그 기록
     * 
     * @param toolName 도구 이름
     * @param action 수행된 작업
     * @param user 작업 수행자
     * @param parameters 파라미터들
     */
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
        
        log.info("AUDIT: {}", auditEntry);
    }
    
    /**
     * 간단한 감사 로그 기록
     * 
     * @param toolName 도구 이름
     * @param message 로그 메시지
     */
    public static void auditLog(String toolName, String message) {
        auditLog(toolName, message, null);
    }
    
    /**
     * 보안 이벤트 로깅
     * 
     * @param severity 심각도 (CRITICAL, HIGH, MEDIUM, LOW)
     * @param eventType 이벤트 타입
     * @param description 설명
     * @param metadata 추가 메타데이터
     */
    public static void logSecurityEvent(String severity, String eventType, 
                                       String description, Map<String, Object> metadata) {
        Map<String, Object> event = new HashMap<>();
        event.put("timestamp", LocalDateTime.now().format(AUDIT_DATE_FORMAT));
        event.put("severity", severity);
        event.put("type", eventType);
        event.put("description", description);
        
        if (metadata != null && !metadata.isEmpty()) {
            event.put("metadata", metadata);
        }
        
        switch (severity.toUpperCase()) {
            case "CRITICAL":
                log.error("SECURITY EVENT: {}", event);
                break;
            case "HIGH":
                log.warn("SECURITY EVENT: {}", event);
                break;
            case "MEDIUM":
                log.info("SECURITY EVENT: {}", event);
                break;
            default:
                log.debug("SECURITY EVENT: {}", event);
        }
    }
    
    /**
     * IPv4 주소 유효성 검증
     * 
     * @param ip IP 주소 문자열
     * @return 유효한 IPv4 주소인 경우 true
     */
    public static boolean isValidIpv4Address(String ip) {
        if (!StringUtils.hasText(ip)) {
            return false;
        }
        return IPV4_PATTERN.matcher(ip.trim()).matches();
    }
    
    /**
     * IPv6 주소 유효성 검증
     * 
     * @param ip IP 주소 문자열
     * @return 유효한 IPv6 주소인 경우 true
     */
    public static boolean isValidIpv6Address(String ip) {
        if (!StringUtils.hasText(ip)) {
            return false;
        }
        return IPV6_PATTERN.matcher(ip.trim()).matches();
    }
    
    /**
     * IP 주소 유효성 검증 (IPv4 또는 IPv6)
     * 
     * @param ip IP 주소 문자열
     * @return 유효한 IP 주소인 경우 true
     */
    public static boolean isValidIpAddress(String ip) {
        return isValidIpv4Address(ip) || isValidIpv6Address(ip);
    }
    
    /**
     * 내부 IP 주소 확인 (RFC 1918)
     * 
     * @param ip IP 주소 문자열
     * @return 내부 IP인 경우 true
     */
    public static boolean isInternalIpAddress(String ip) {
        if (!isValidIpv4Address(ip)) {
            return false;
        }
        
        String trimmedIp = ip.trim();
        
        // 10.0.0.0/8
        if (trimmedIp.startsWith("10.")) {
            return true;
        }
        
        // 172.16.0.0/12
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
        
        // 192.168.0.0/16
        if (trimmedIp.startsWith("192.168.")) {
            return true;
        }
        
        // 127.0.0.0/8 (loopback)
        if (trimmedIp.startsWith("127.")) {
            return true;
        }
        
        // 169.254.0.0/16 (link-local)
        if (trimmedIp.startsWith("169.254.")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 도메인 이름 유효성 검증
     * 
     * @param domain 도메인 이름
     * @return 유효한 도메인인 경우 true
     */
    public static boolean isValidDomain(String domain) {
        if (!StringUtils.hasText(domain)) {
            return false;
        }
        
        // 최대 길이 체크 (253자)
        if (domain.length() > 253) {
            return false;
        }
        
        return DOMAIN_PATTERN.matcher(domain.trim()).matches();
    }
    
    /**
     * 포트 번호 유효성 검증
     * 
     * @param port 포트 번호
     * @return 유효한 포트 번호인 경우 true (1-65535)
     */
    public static boolean isValidPort(int port) {
        return port >= 1 && port <= 65535;
    }
    
    /**
     * 포트 번호 유효성 검증 (문자열)
     * 
     * @param portStr 포트 번호 문자열
     * @return 유효한 포트 번호인 경우 true
     */
    public static boolean isValidPort(String portStr) {
        if (!StringUtils.hasText(portStr)) {
            return false;
        }
        return PORT_PATTERN.matcher(portStr.trim()).matches();
    }
    
    /**
     * 로그 출력을 위한 문자열 sanitization
     * 민감한 정보나 injection 공격 방지
     * 
     * @param input 원본 문자열
     * @return sanitized 문자열
     */
    public static String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        
        // 최대 길이 제한 (500자)
        String sanitized = input.length() > 500 
            ? input.substring(0, 497) + "..." 
            : input;
        
        // 개행 문자 및 특수 문자 제거/치환
        sanitized = sanitized
            .replaceAll("[\r\n]", " ")
            .replaceAll("\\p{Cntrl}", "")
            .replaceAll("password=\\S+", "password=***")
            .replaceAll("token=\\S+", "token=***")
            .replaceAll("apikey=\\S+", "apikey=***")
            .replaceAll("secret=\\S+", "secret=***");
        
        return sanitized;
    }
    
    /**
     * 위협 레벨 계산
     * 
     * @param score 위협 점수 (0-100)
     * @return 위협 레벨 (CRITICAL, HIGH, MEDIUM, LOW, MINIMAL)
     */
    public static String calculateThreatLevel(int score) {
        if (score >= 80) return "CRITICAL";
        if (score >= 60) return "HIGH";
        if (score >= 40) return "MEDIUM";
        if (score >= 20) return "LOW";
        return "MINIMAL";
    }
    
    /**
     * 실행 시간 측정 및 로깅
     * 
     * @param toolName 도구 이름
     * @param operation 작업 이름
     * @param startTime 시작 시간 (System.currentTimeMillis())
     */
    public static void logExecutionTime(String toolName, String operation, long startTime) {
        long duration = System.currentTimeMillis() - startTime;
        
        if (duration > 5000) {
            log.warn("SLOW OPERATION: Tool={}, Operation={}, Duration={}ms", 
                    toolName, operation, duration);
        } else {
            log.debug("Operation completed: Tool={}, Operation={}, Duration={}ms", 
                     toolName, operation, duration);
        }
    }
    
    /**
     * 입력 검증 헬퍼
     * 
     * @param value 검증할 값
     * @param fieldName 필드 이름
     * @throws IllegalArgumentException 값이 null이거나 비어있는 경우
     */
    public static void requireNonEmpty(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(fieldName + " is required and cannot be empty");
        }
    }
    
    /**
     * 입력 검증 헬퍼 (객체)
     * 
     * @param value 검증할 값
     * @param fieldName 필드 이름
     * @throws IllegalArgumentException 값이 null인 경우
     */
    public static void requireNonNull(Object value, String fieldName) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " is required and cannot be null");
        }
    }
    
    /**
     * 범위 검증 헬퍼
     * 
     * @param value 검증할 값
     * @param min 최소값
     * @param max 최대값
     * @param fieldName 필드 이름
     * @throws IllegalArgumentException 값이 범위를 벗어난 경우
     */
    public static void requireInRange(int value, int min, int max, String fieldName) {
        if (value < min || value > max) {
            throw new IllegalArgumentException(
                String.format("%s must be between %d and %d, but was %d", 
                             fieldName, min, max, value)
            );
        }
    }
    
    /**
     * 보안 메트릭 수집
     * 
     * @param toolName 도구 이름
     * @param metricName 메트릭 이름
     * @param value 메트릭 값
     */
    public static void recordMetric(String toolName, String metricName, Object value) {
        log.debug("METRIC: Tool={}, Metric={}, Value={}", toolName, metricName, value);
        // 실제 환경에서는 Micrometer 등의 메트릭 라이브러리와 통합
    }
    
    /**
     * 작업 결과 포맷팅
     * 
     * @param success 성공 여부
     * @param message 메시지
     * @param details 추가 상세 정보
     * @return 포맷팅된 결과 맵
     */
    public static Map<String, Object> formatResult(boolean success, String message, 
                                                   Map<String, Object> details) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", success);
        result.put("message", message);
        result.put("timestamp", LocalDateTime.now().format(AUDIT_DATE_FORMAT));
        
        if (details != null && !details.isEmpty()) {
            result.put("details", details);
        }
        
        return result;
    }
}