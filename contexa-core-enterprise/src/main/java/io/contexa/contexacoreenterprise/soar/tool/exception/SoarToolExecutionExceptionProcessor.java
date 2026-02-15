package io.contexa.contexacoreenterprise.soar.tool.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.execution.DefaultToolExecutionExceptionProcessor;
import org.springframework.ai.tool.execution.ToolExecutionException;
import org.springframework.ai.tool.execution.ToolExecutionExceptionProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;

@Slf4j
public class SoarToolExecutionExceptionProcessor implements ToolExecutionExceptionProcessor {
    
    private final boolean throwOnError;
    private final DefaultToolExecutionExceptionProcessor defaultProcessor;
    private final ObjectMapper objectMapper;

    private final Map<String, Integer> retryCounters = new ConcurrentHashMap<>();
    private final Map<String, RecoveryStrategy> recoveryStrategies = new ConcurrentHashMap<>();
    
    public SoarToolExecutionExceptionProcessor(
            @Value("${spring.ai.tools.throw-exception-on-error:false}") boolean throwOnError) {
        this.throwOnError = throwOnError;
        this.defaultProcessor = new DefaultToolExecutionExceptionProcessor(throwOnError);
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
            }
    
    @Override
    public String process(ToolExecutionException exception) {
        String toolName = exception.getToolDefinition().name();
        Throwable cause = exception.getCause();
        
        log.error("Tool execution exception - tool: {}, exception: {}", toolName, cause != null ? cause.getMessage() : "Unknown", cause);

        if (throwOnError) {
            
            if (cause instanceof PermissionDeniedException || 
                cause instanceof ApprovalTimeoutException) {
                throw new SecurityToolExecutionException(
                    "Security tool execution failed: " + cause.getMessage(), exception);
            }
            
            return defaultProcessor.process(exception);
        }

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

    private String handleTimeoutException(String toolName, ToolExecutionException exception) {
        log.error("Tool execution timeout: {}", toolName);

        return createErrorResponse(
            "TIMEOUT",
            "Tool execution timed out",
            Map.of(
                "toolName", toolName,
                "suggestedAction", "Retry with extended timeout",
                "retryable", true,
                "extendedTimeoutMs", 60000,
                "timestamp", Instant.now()
            )
        );
    }

    private String handleApprovalTimeout(String toolName, ToolExecutionException exception) {
        log.error("Approval timeout: {} - escalating", toolName);

        escalateToSupervisor(toolName);

        return createErrorResponse(
            "APPROVAL_TIMEOUT",
            "Approval response timed out, escalated to supervisor",
            Map.of(
                "toolName", toolName,
                "escalated", true,
                "escalatedTo", "supervisor",
                "escalationTime", Instant.now(),
                "retryable", false
            )
        );
    }

    private String handleRateLimitExceeded(String toolName, ToolExecutionException exception) {
        log.error("Rate limit exceeded: {}", toolName);

        return createErrorResponse(
            "RATE_LIMIT_EXCEEDED",
            "Tool execution rate limit exceeded",
            Map.of(
                "toolName", toolName,
                "suggestedAction", "Queued for later execution",
                "retryable", true,
                "retryAfterMs", 60000,
                "queuedForMs", 60000,
                "timestamp", Instant.now()
            )
        );
    }

    private String handlePermissionDenied(String toolName, ToolExecutionException exception) {
        log.error("Permission denied: {}", toolName);

        return createErrorResponse(
            "PERMISSION_DENIED",
            "No permission to execute tool",
            Map.of(
                "toolName", toolName,
                "suggestedAction", "Initiate permission request process",
                "retryable", false,
                "requestUrl", "/api/permissions/request",
                "timestamp", Instant.now()
            )
        );
    }

    private String handleNetworkException(String toolName, ToolExecutionException exception) {
        log.error("Network exception: {} - applying recovery strategy", toolName);

        RecoveryStrategy strategy = getRecoveryStrategy(toolName);

        return createErrorResponse(
            "NETWORK_ERROR",
            "Network communication error",
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

    private String handleValidationException(String toolName, ToolExecutionException exception) {
        log.error("Input validation failed: {}", toolName);

        return createErrorResponse(
            "VALIDATION_ERROR",
            "Input parameter validation failed",
            Map.of(
                "toolName", toolName,
                "suggestedAction", "Fix parameters and retry",
                "retryable", false,
                "validationErrors", "Parameter format is invalid",
                "timestamp", Instant.now()
            )
        );
    }

    private String handleGenericException(String toolName, ToolExecutionException exception, Throwable cause) {
        log.error("Generic exception occurred: {} - {}", toolName, cause.getMessage());
        
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

    private String createErrorResponse(String errorType, String errorMessage, Map<String, Object> details) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("success", false);
        response.put("errorType", errorType);
        response.put("errorMessage", errorMessage);
        response.put("details", details);
        try {
            return objectMapper.writeValueAsString(response);
        } catch (Exception e) {
            log.error("JSON serialization failed", e);
            return "{\"success\":false,\"errorType\":\"SERIALIZATION_ERROR\"}";
        }
    }

    private void escalateToSupervisor(String toolName) {
                
    }

    private RecoveryStrategy getRecoveryStrategy(String toolName) {
        return recoveryStrategies.getOrDefault(toolName, 
            new RecoveryStrategy(true, 3, 1000L));
    }

    private String getAlternativeAction(String toolName) {
        if ("network_isolation".equals(toolName)) {
            return "Fallback to firewall rules execution";
        }
        return "Retry or manual processing";
    }

    private int getRetryCount(String toolName) {
        return retryCounters.getOrDefault(toolName, 0);
    }

    private boolean isRetryableException(Throwable cause) {
        return !(cause instanceof IllegalArgumentException ||
                cause instanceof IllegalStateException ||
                cause instanceof SecurityException ||
                cause instanceof PermissionDeniedException);
    }

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