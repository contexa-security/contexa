package io.contexa.contexacore.std.advisor.soar;

import io.contexa.contexacore.std.advisor.core.DomainPolicy;
import io.contexa.contexacommon.annotation.SoarTool;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.tool.ToolCallback;

import java.util.List;
import java.util.Map;

/**
 * SOAR 도메인 정책
 * 
 * SOAR 도메인에서 적용되는 정책을 정의합니다.
 * - 도구 실행 승인 정책
 * - 위험도 평가 정책
 * - 실행 제한 정책
 */
@Slf4j
@RequiredArgsConstructor
public class SoarDomainPolicy implements DomainPolicy {
    
    private final Map<String, Object> policyConfig;
    private final boolean enabled;
    
    @Override
    public String getName() {
        return "SOAR_DOMAIN_POLICY";
    }
    
    @Override
    public boolean isEnabled() {
        return enabled;
    }
    
    @Override
    public ChatClientRequest apply(ChatClientRequest request) {
        if (!enabled) {
            return request;
        }
        
        // 도구 실행 정책 적용
        applyToolExecutionPolicy(request);
        
        // 위험도 기반 정책 적용
        applyRiskBasedPolicy(request);
        
        // 실행 제한 정책 적용
        applyExecutionLimitPolicy(request);
        
        return request;
    }
    
    @Override
    public boolean validate(ChatClientRequest request) {
        // 기본 검증
        if (request == null || request.prompt() == null) {
            return false;
        }
        
        // 고위험 도구 검증
        if (!validateHighRiskTools(request)) {
            log.warn("High risk tool validation failed");
            return false;
        }
        
        // 실행 권한 검증
        if (!validateExecutionPermissions(request)) {
            log.warn("Execution permission validation failed");
            return false;
        }
        
        return true;
    }
    
    @Override
    public String getDescription() {
        return "SOAR domain policy for tool execution approval, risk assessment, and execution limits";
    }
    
    /**
     * 도구 실행 정책 적용
     */
    private void applyToolExecutionPolicy(ChatClientRequest request) {
        Boolean requireApproval = (Boolean) policyConfig.get("require.approval");
        if (requireApproval != null && requireApproval) {
            request.context().put("soar.policy.approval.required", true);
        }
        
        Integer maxConcurrentTools = (Integer) policyConfig.get("max.concurrent.tools");
        if (maxConcurrentTools != null) {
            request.context().put("soar.policy.max.concurrent", maxConcurrentTools);
        }
    }
    
    /**
     * 위험도 기반 정책 적용
     */
    private void applyRiskBasedPolicy(ChatClientRequest request) {
        String riskThreshold = (String) policyConfig.get("risk.threshold");
        if (riskThreshold != null) {
            SoarTool.RiskLevel threshold = SoarTool.RiskLevel.valueOf(riskThreshold);
            request.context().put("soar.policy.risk.threshold", threshold);
            
            // 고위험 도구 자동 거부 정책
            if (threshold == SoarTool.RiskLevel.LOW) {
                request.context().put("soar.policy.deny.high.risk", true);
            }
        }
    }
    
    /**
     * 실행 제한 정책 적용
     */
    private void applyExecutionLimitPolicy(ChatClientRequest request) {
        Integer timeoutSeconds = (Integer) policyConfig.get("execution.timeout.seconds");
        if (timeoutSeconds != null) {
            request.context().put("soar.policy.timeout", timeoutSeconds);
        }
        
        Integer maxRetries = (Integer) policyConfig.get("execution.max.retries");
        if (maxRetries != null) {
            request.context().put("soar.policy.max.retries", maxRetries);
        }
    }
    
    /**
     * 고위험 도구 검증
     */
    private boolean validateHighRiskTools(ChatClientRequest request) {
        if (request.prompt().getOptions() instanceof ToolCallingChatOptions toolOptions) {
            List<ToolCallback> callbacks = toolOptions.getToolCallbacks();
            
            if (callbacks != null) {
                for (ToolCallback callback : callbacks) {
                    String toolName = callback.getToolDefinition().name();
                    
                    // 차단 목록 확인
                    @SuppressWarnings("unchecked")
                    List<String> blockedTools = (List<String>) policyConfig.get("blocked.tools");
                    if (blockedTools != null && blockedTools.contains(toolName)) {
                        log.error("Blocked tool detected: {}", toolName);
                        return false;
                    }
                }
            }
        }
        
        return true;
    }
    
    /**
     * 실행 권한 검증
     */
    private boolean validateExecutionPermissions(ChatClientRequest request) {
        // 사용자 권한 확인
        String user = (String) request.context().get("user.id");
        if (user == null) {
            log.warn("No user context found");
            return false;
        }
        
        // 최소 권한 레벨 확인
        String minRole = (String) policyConfig.get("min.role.level");
        if (minRole != null) {
            String userRole = (String) request.context().get("user.role");
            if (userRole == null || !hasMinimumRole(userRole, minRole)) {
                log.warn("User {} does not have minimum role: {}", user, minRole);
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 최소 권한 레벨 확인
     */
    private boolean hasMinimumRole(String userRole, String minRole) {
        // 간단한 역할 계층 구조
        Map<String, Integer> roleHierarchy = Map.of(
            "ADMIN", 100,
            "SECURITY_ANALYST", 80,
            "OPERATOR", 60,
            "VIEWER", 20
        );
        
        Integer userLevel = roleHierarchy.get(userRole);
        Integer minLevel = roleHierarchy.get(minRole);
        
        return userLevel != null && minLevel != null && userLevel >= minLevel;
    }
}