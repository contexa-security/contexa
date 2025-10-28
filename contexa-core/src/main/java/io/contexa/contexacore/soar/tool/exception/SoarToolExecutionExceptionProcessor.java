package io.contexa.contexacore.soar.tool.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.execution.DefaultToolExecutionExceptionProcessor;
import org.springframework.ai.tool.execution.ToolExecutionException;
import org.springframework.ai.tool.execution.ToolExecutionExceptionProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;

/**
 * SOAR 도구 실행 예외 처리기
 * Spring AI의 ToolExecutionExceptionProcessor를 확장하여 보안 도구 특화 처리
 * 
 * 특징:
 * - 보안 도구 특화 예외 처리 (승인 타임아웃, 권한 거부 등)
 * - 에스컬레이션 및 복구 전략
 * - 구조화된 JSON 오류 응답
 * - DefaultToolExecutionExceptionProcessor와 통합
 */
@Slf4j
public class SoarToolExecutionExceptionProcessor implements ToolExecutionExceptionProcessor {
    
    private final boolean throwOnError;
    private final DefaultToolExecutionExceptionProcessor defaultProcessor;
    
    private final Map<String, Integer> retryCounters = new ConcurrentHashMap<>();
    private final Map<String, RecoveryStrategy> recoveryStrategies = new ConcurrentHashMap<>();
    
    public SoarToolExecutionExceptionProcessor(
            @Value("${spring.ai.tools.throw-exception-on-error:false}") boolean throwOnError) {
        this.throwOnError = throwOnError;
        this.defaultProcessor = new DefaultToolExecutionExceptionProcessor(throwOnError);
        log.info("SOAR Tool Execution Exception Processor 초기화 (throwOnError: {})", throwOnError);
    }
    
    @Override
    public String process(ToolExecutionException exception) {
        String toolName = exception.getToolDefinition().name();
        Throwable cause = exception.getCause();
        
        log.error("도구 실행 예외 발생 - 도구: {}, 예외: {}", toolName, cause != null ? cause.getMessage() : "Unknown", cause);
        
        // throwOnError가 true면 예외를 다시 던짐
        if (throwOnError) {
            // 보안 관련 예외는 무조건 던짐
            if (cause instanceof PermissionDeniedException || 
                cause instanceof ApprovalTimeoutException) {
                throw new SecurityToolExecutionException(
                    "보안 도구 실행 실패: " + cause.getMessage(), exception);
            }
            // 기본 처리기에 위임
            return defaultProcessor.process(exception);
        }
        
        // throwOnError가 false면 구조화된 오류 메시지 반환
        if (cause instanceof TimeoutException) {
            return handleTimeoutException(toolName, exception);
        } else if (cause instanceof ApprovalTimeoutException) {
            return handleApprovalTimeout(toolName, exception);
        } else if (cause instanceof RateLimitExceededException) {
            return handleRateLimitExceeded(toolName, exception);
        } else if (cause instanceof PermissionDeniedException) {
            return handlePermissionDenied(toolName, exception);
        } else if (cause instanceof NetworkException) {
            return handleNetworkException(toolName, exception);
        } else if (cause instanceof ValidationException) {
            return handleValidationException(toolName, exception);
        } else {
            return handleGenericException(toolName, exception, cause);
        }
    }
    
    /**
     * 타임아웃 예외 처리
     */
    private String handleTimeoutException(String toolName, ToolExecutionException exception) {
        log.warn("⏰ 도구 실행 타임아웃: {}", toolName);
        
        return createErrorResponse(
            "TIMEOUT",
            "도구 실행 시간 초과",
            Map.of(
                "toolName", toolName,
                "suggestedAction", "타임아웃을 연장하여 재시도",
                "retryable", true,
                "extendedTimeoutMs", 60000,
                "timestamp", Instant.now()
            )
        );
    }
    
    /**
     * 승인 타임아웃 처리
     */
    private String handleApprovalTimeout(String toolName, ToolExecutionException exception) {
        log.warn("⏰ 승인 타임아웃: {} - 에스컬레이션 진행", toolName);
        
        // 에스컬레이션 로직
        escalateToSupervisor(toolName);
        
        return createErrorResponse(
            "APPROVAL_TIMEOUT",
            "승인 응답 시간 초과로 상위 관리자에게 에스컬레이션",
            Map.of(
                "toolName", toolName,
                "escalated", true,
                "escalatedTo", "supervisor",
                "escalationTime", Instant.now(),
                "retryable", false
            )
        );
    }
    
    /**
     * Rate Limit 초과 처리
     */
    private String handleRateLimitExceeded(String toolName, ToolExecutionException exception) {
        log.warn("🚫 Rate limit 초과: {}", toolName);
        
        return createErrorResponse(
            "RATE_LIMIT_EXCEEDED",
            "도구 실행 빈도 제한 초과",
            Map.of(
                "toolName", toolName,
                "suggestedAction", "실행 대기열에 추가하여 나중에 실행",
                "retryable", true,
                "retryAfterMs", 60000,
                "queuedForMs", 60000,
                "timestamp", Instant.now()
            )
        );
    }
    
    /**
     * 권한 거부 처리
     */
    private String handlePermissionDenied(String toolName, ToolExecutionException exception) {
        log.error("권한 거부: {}", toolName);
        
        return createErrorResponse(
            "PERMISSION_DENIED",
            "도구 실행 권한이 없습니다",
            Map.of(
                "toolName", toolName,
                "suggestedAction", "권한 요청 프로세스 시작",
                "retryable", false,
                "requestUrl", "/api/permissions/request",
                "timestamp", Instant.now()
            )
        );
    }
    
    /**
     * 네트워크 예외 처리
     */
    private String handleNetworkException(String toolName, ToolExecutionException exception) {
        log.warn("네트워크 예외: {} - 복구 전략 적용", toolName);
        
        RecoveryStrategy strategy = getRecoveryStrategy(toolName);
        
        return createErrorResponse(
            "NETWORK_ERROR",
            "네트워크 통신 오류",
            Map.of(
                "toolName", toolName,
                "suggestedAction", getAlternativeAction(toolName),
                "retryable", strategy.isRetryable(),
                "maxRetries", strategy.getMaxRetries(),
                "retryDelayMs", strategy.getRetryDelayMs(),
                "attemptCount", getRetryCount(toolName),
                "timestamp", Instant.now()
            )
        );
    }
    
    /**
     * 검증 예외 처리
     */
    private String handleValidationException(String toolName, ToolExecutionException exception) {
        log.warn("입력 검증 실패: {}", toolName);
        
        return createErrorResponse(
            "VALIDATION_ERROR",
            "입력 매개변수 검증 실패",
            Map.of(
                "toolName", toolName,
                "suggestedAction", "매개변수를 수정하고 재시도",
                "retryable", false,
                "validationErrors", "매개변수 형식이 올바르지 않습니다",
                "timestamp", Instant.now()
            )
        );
    }
    
    /**
     * 일반 예외 처리
     */
    private String handleGenericException(String toolName, ToolExecutionException exception, Throwable cause) {
        log.error("💥 일반 예외 발생: {} - {}", toolName, cause.getMessage());
        
        boolean isRetryable = isRetryableException(cause);
        int retryCount = getRetryCount(toolName);
        
        return createErrorResponse(
            "GENERIC_ERROR",
            cause.getMessage(),
            Map.of(
                "toolName", toolName,
                "retryable", isRetryable && retryCount < 3,
                "currentRetryCount", retryCount,
                "maxRetries", 3,
                "exceptionClass", cause.getClass().getName(),
                "timestamp", Instant.now()
            )
        );
    }
    
    /**
     * JSON 형태의 오류 응답 생성
     */
    private String createErrorResponse(String errorType, String errorMessage, Map<String, Object> details) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"success\": false,\n");
        json.append("  \"errorType\": \"").append(errorType).append("\",\n");
        json.append("  \"errorMessage\": \"").append(errorMessage).append("\",\n");
        json.append("  \"details\": {\n");
        
        int count = 0;
        for (Map.Entry<String, Object> entry : details.entrySet()) {
            if (count > 0) json.append(",\n");
            json.append("    \"").append(entry.getKey()).append("\": ");
            
            Object value = entry.getValue();
            if (value instanceof String) {
                json.append("\"").append(value).append("\"");
            } else if (value instanceof Boolean || value instanceof Number) {
                json.append(value);
            } else {
                json.append("\"").append(value.toString()).append("\"");
            }
            count++;
        }
        
        json.append("\n  }\n}");
        return json.toString();
    }
    
    /**
     * 에스컬레이션 처리
     */
    private void escalateToSupervisor(String toolName) {
        log.info("에스컬레이션 시작: {} -> 상위 관리자", toolName);
        // 실제 구현에서는 알림 서비스 호출
    }
    
    /**
     * 복구 전략 조회
     */
    private RecoveryStrategy getRecoveryStrategy(String toolName) {
        return recoveryStrategies.getOrDefault(toolName, 
            new RecoveryStrategy(true, 3, 1000L));
    }
    
    /**
     * 대체 액션 조회
     */
    private String getAlternativeAction(String toolName) {
        if ("network_isolation".equals(toolName)) {
            return "방화벽 규칙으로 대체 실행";
        }
        return "재시도 또는 수동 처리";
    }
    
    /**
     * 재시도 횟수 조회
     */
    private int getRetryCount(String toolName) {
        return retryCounters.getOrDefault(toolName, 0);
    }
    
    /**
     * 재시도 가능 예외 판단
     */
    private boolean isRetryableException(Throwable cause) {
        return !(cause instanceof IllegalArgumentException ||
                cause instanceof IllegalStateException ||
                cause instanceof SecurityException ||
                cause instanceof PermissionDeniedException);
    }
    
    /**
     * 복구 전략
     */
    public static class RecoveryStrategy {
        private final boolean retryable;
        private final int maxRetries;
        private final long retryDelayMs;
        
        public RecoveryStrategy(boolean retryable, int maxRetries, long retryDelayMs) {
            this.retryable = retryable;
            this.maxRetries = maxRetries;
            this.retryDelayMs = retryDelayMs;
        }
        
        public boolean isRetryable() { return retryable; }
        public int getMaxRetries() { return maxRetries; }
        public long getRetryDelayMs() { return retryDelayMs; }
    }
    
    /**
     * 보안 도구 실행 예외
     */
    public static class SecurityToolExecutionException extends RuntimeException {
        private final ToolExecutionException originalException;
        
        public SecurityToolExecutionException(String message, ToolExecutionException originalException) {
            super(message, originalException);
            this.originalException = originalException;
        }
        
        public ToolExecutionException getOriginalException() {
            return originalException;
        }
    }
    
    /**
     * 커스텀 예외 클래스들
     */
    public static class ApprovalTimeoutException extends RuntimeException {
        public ApprovalTimeoutException(String message) {
            super(message);
        }
    }
    
    public static class RateLimitExceededException extends RuntimeException {
        public RateLimitExceededException(String message) {
            super(message);
        }
    }
    
    public static class PermissionDeniedException extends RuntimeException {
        public PermissionDeniedException(String message) {
            super(message);
        }
    }
    
    public static class NetworkException extends RuntimeException {
        public NetworkException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    public static class ValidationException extends RuntimeException {
        public ValidationException(String message) {
            super(message);
        }
    }
}