package io.contexa.contexacoreenterprise.mcp.tool.execution;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

/**
 * Container for tool execution model classes.
 * Used by ToolAuthorizationService for authorization and approval workflows.
 */
public interface ToolExecutor {

    @Data
    @Builder
    class ToolRequest {
        private String toolName;
        private Map<String, Object> parameters;
        private Map<String, String> headers;
        private String rawInput;
        
        public String toJson() {
            
            return rawInput != null ? rawInput : "{}";
        }
        
        @Override
        public int hashCode() {
            return java.util.Objects.hash(toolName, parameters);
        }
    }
    
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