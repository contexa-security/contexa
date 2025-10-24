package io.contexa.contexacore.mcp.tool.execution;

import lombok.Builder;
import lombok.Data;
import org.springframework.ai.tool.ToolCallback;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * ToolExecutor 인터페이스
 * 
 * 도구 실행을 위한 표준 인터페이스입니다.
 */
public interface ToolExecutor {
    
    /**
     * 도구 실행
     */
    CompletableFuture<ToolResult> execute(
        ToolCallback tool,
        ToolRequest request,
        ExecutionContext context
    );
    
    /**
     * 도구 요청
     */
    @Data
    @Builder
    class ToolRequest {
        private String toolName;
        private Map<String, Object> parameters;
        private Map<String, String> headers;
        private String rawInput;
        
        public String toJson() {
            // JSON 변환 로직
            return rawInput != null ? rawInput : "{}";
        }
        
        @Override
        public int hashCode() {
            return toolName.hashCode() + parameters.hashCode();
        }
    }
    
    /**
     * 실행 컨텍스트
     */
    @Data
    @Builder
    class ExecutionContext {
        private String sessionId;
        private String userId;
        private String tenantId;
        private boolean productionEnvironment;
        private Map<String, Object> attributes;
        
        public boolean isProductionEnvironment() {
            return productionEnvironment;
        }
    }
    
    /**
     * 도구 실행 결과
     */
    @Data
    @Builder
    class ToolResult {
        private String toolName;
        private String result;
        private long executionTime;
        private boolean success;
        private String error;
        private Map<String, Object> metadata;
    }
    
    /**
     * 승인 요청
     */
    @Data
    @Builder
    class ApprovalRequest {
        private String toolName;
        private ToolRequest request;
        private ExecutionContext context;
        private long requestTime;
        private String approver;
        private boolean approved;
        private String reason;
    }
}