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
        
        
        applyToolExecutionPolicy(request);
        
        
        applyRiskBasedPolicy(request);
        
        
        applyExecutionLimitPolicy(request);
        
        return request;
    }
    
    @Override
    public boolean validate(ChatClientRequest request) {
        
        if (request == null || request.prompt() == null) {
            return false;
        }
        
        
        if (!validateHighRiskTools(request)) {
            log.warn("High risk tool validation failed");
            return false;
        }
        
        
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
    
    
    private void applyRiskBasedPolicy(ChatClientRequest request) {
        String riskThreshold = (String) policyConfig.get("risk.threshold");
        if (riskThreshold != null) {
            SoarTool.RiskLevel threshold = SoarTool.RiskLevel.valueOf(riskThreshold);
            request.context().put("soar.policy.risk.threshold", threshold);
            
            
            if (threshold == SoarTool.RiskLevel.LOW) {
                request.context().put("soar.policy.deny.high.risk", true);
            }
        }
    }
    
    
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
    
    
    private boolean validateHighRiskTools(ChatClientRequest request) {
        if (request.prompt().getOptions() instanceof ToolCallingChatOptions toolOptions) {
            List<ToolCallback> callbacks = toolOptions.getToolCallbacks();
            
            if (callbacks != null) {
                for (ToolCallback callback : callbacks) {
                    String toolName = callback.getToolDefinition().name();
                    
                    
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
    
    
    private boolean validateExecutionPermissions(ChatClientRequest request) {
        
        String user = (String) request.context().get("user.id");
        if (user == null) {
            log.warn("No user context found");
            return false;
        }
        
        
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
    
    
    private boolean hasMinimumRole(String userRole, String minRole) {
        
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