package io.contexa.contexacore.std.advisor.soar;

import io.opentelemetry.api.trace.Tracer;
import io.contexa.contexacore.std.advisor.core.DomainAdvisor;
import io.contexa.contexacore.std.advisor.core.AdvisorContext;
import io.contexa.contexacore.std.advisor.core.DomainPolicy;
import io.contexa.contexacore.std.advisor.core.SharedAdvisorContext;
import io.contexa.contexacommon.soar.config.ToolApprovalPolicyManager;
import io.contexa.contexacommon.soar.metrics.ToolExecutionMetrics;
import io.contexa.contexacommon.annotation.SoarTool;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import java.time.LocalDateTime;
import java.util.*;

@Slf4j
public class EnhancedSoarApprovalAdvisor extends DomainAdvisor implements ApplicationContextAware {
    
    private static final String DOMAIN_NAME = "SOAR";
    private static final String ADVISOR_NAME = "tool-policy";
    private static final String TOOL_RISK_KEY = "soar.tool.risk_levels";
    private static final String FILTERED_TOOLS_KEY = "soar.tool.filtered";
    private static final String ALLOWED_TOOLS_KEY = "soar.tool.allowed";
    private static final String TOOL_METADATA_KEY = "soar.tool.metadata";
    
    private ApplicationContext applicationContext;
    private ToolApprovalPolicyManager policyManager;
    private ToolExecutionMetrics executionMetrics;
    private SharedAdvisorContext sharedContext;
    
    @Value("${contexa.advisor.soar.approval.order:100}")
    private int advisorOrder;
    
    @Value("${contexa.advisor.soar.approval.enabled:true}")
    private boolean advisorEnabled;
    
    @Value("${contexa.advisor.soar.approval.timeout:300}")
    private int defaultTimeoutSeconds;

    public EnhancedSoarApprovalAdvisor(Tracer tracer) {
        super(tracer, DOMAIN_NAME, ADVISOR_NAME, 100, null, new HashMap<>());
    }
    
    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;

        try {
            this.policyManager = applicationContext.getBean(ToolApprovalPolicyManager.class);
            this.executionMetrics = applicationContext.getBean(ToolExecutionMetrics.class);
            this.sharedContext = applicationContext.getBean(SharedAdvisorContext.class);
        } catch (Exception e) {
            log.warn("의존성 주입 실패, PostConstruct에서 재시도: {}", e.getMessage());
        }
    }
    
    @PostConstruct
    public void init() {
        
        if (policyManager == null || executionMetrics == null || sharedContext == null) {
            try {
                if (applicationContext != null) {
                    this.policyManager = applicationContext.getBean(ToolApprovalPolicyManager.class);
                    this.executionMetrics = applicationContext.getBean(ToolExecutionMetrics.class);
                    this.sharedContext = applicationContext.getBean(SharedAdvisorContext.class);
                }
            } catch (Exception e) {
                log.error("PostConstruct에서 의존성 주입 실패: {}", e.getMessage());
                return;
            }
        }

        if (sharedContext == null) {
            log.warn("SharedAdvisorContext가 없어 초기화를 건너뜀");
            return;
        }

        AdvisorContext context = sharedContext.getDomainContext(DOMAIN_NAME);
        context.setAttribute("advisor.type", "tool-policy");
        context.setAttribute("initialized", LocalDateTime.now());
        context.setAttribute("filtering.enabled", true);

        setEnabled(advisorEnabled);
        
            }
    
    @Override
    public int getOrder() {
        return advisorOrder;
    }
    
    @Override
    protected DomainPolicy createDomainPolicy() {
        Map<String, Object> policyConfig = new HashMap<>();
        policyConfig.put("require.approval", true);
        policyConfig.put("risk.threshold", "HIGH");
        policyConfig.put("execution.timeout.seconds", defaultTimeoutSeconds);
        policyConfig.put("max.concurrent.tools", 5);

        policyConfig.put("blocked.tools", List.of("system_shutdown", "data_delete_all"));

        policyConfig.put("min.role.level", "OPERATOR");
        
        return new SoarDomainPolicy(policyConfig, true);
    }
    
    @Override
    protected boolean validateDomainRequest(ChatClientRequest request) {
        
        String sessionId = (String) request.context().get("session.id");
        String userId = (String) request.context().get("user.id");
        Boolean authenticated = (Boolean) request.context().get("authenticated");

        if (!isProductionEnvironment()) {
            
            if (sessionId == null || userId == null) {
                            }
            return true;
        }

        if (sessionId == null || sessionId.isEmpty()) {
            log.warn("프로덕션 환경 - 세션 ID 누락");
            return false;
        }
        
        if (userId == null || userId.isEmpty()) {
            log.warn("프로덕션 환경 - 사용자 ID 누락");
            return false;
        }

        if ("anonymous".equals(userId)) {

            return true;
        }
        
        return true;
    }

    private boolean isProductionEnvironment() {
        String profile = System.getProperty("spring.profiles.active", "dev");
        return "prod".equals(profile) || "production".equals(profile);
    }
    
    @Override
    protected boolean performSecurityCheck(ChatClientRequest request) {

        if (!checkRateLimit(request)) {
            log.warn("Rate limit exceeded");
            return false;
        }

        if (!checkConcurrentExecutions(request)) {
            log.warn("Concurrent execution limit exceeded");
            return false;
        }
        
        return true;
    }
    
    @Override
    protected ChatClientRequest beforeCall(ChatClientRequest request) {
        
        request = super.beforeCall(request);

        if (policyManager == null) {
            log.warn("ToolApprovalPolicyManager가 없어 필터링을 건너뜀");
            return request;
        }

        FilteringResult filteringResult = applyToolPolicyFiltering(request);

        request.context().put(ALLOWED_TOOLS_KEY, filteringResult.getAllowedTools());
        request.context().put(FILTERED_TOOLS_KEY, filteringResult.getFilteredTools());
        request.context().put(TOOL_RISK_KEY, filteringResult.getToolRiskMap());
        request.context().put(TOOL_METADATA_KEY, filteringResult.getToolMetadata());

        if (!filteringResult.getHighRiskTools().isEmpty() && sharedContext != null) {
                        try {
                sharedContext.shareAcrossDomains(
                    "tool.high_risk.detected",
                    filteringResult.getHighRiskTools(),
                    DOMAIN_NAME,
                    Set.of("IAM", "COMPLIANCE") 
                );
            } catch (Exception e) {
                log.warn("도메인 간 정보 공유 실패: {}", e.getMessage());
            }
        }

        if (!filteringResult.getFilteredTools().isEmpty()) {
            log.warn("🚫 정책에 의해 차단된 도구: {}", filteringResult.getFilteredTools());
            for (String toolName : filteringResult.getFilteredTools()) {
                recordMetric("soar.tool.filtered", 1);
                if (executionMetrics != null) {
                    try {
                        executionMetrics.recordFiltered(toolName, "policy_blocked");
                    } catch (Exception e) {
                        log.warn("메트릭 기록 실패: {}", e.getMessage());
                    }
                }
            }
        }

        for (String toolName : filteringResult.getAllowedTools()) {
            recordMetric("soar.tool.allowed", 1);
        }
        
        return request;
    }
    
    @Override
    protected ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request) {
        
        response = super.afterCall(response, request);

        if (sharedContext != null) {
            @SuppressWarnings("unchecked")
            List<String> allowedTools = (List<String>) request.context().get(ALLOWED_TOOLS_KEY);
            if (allowedTools != null && !allowedTools.isEmpty()) {
                try {
                    sharedContext.shareAcrossDomains(
                        "tool.execution.completed",
                        Map.of(
                            "tools", allowedTools,
                            "timestamp", System.currentTimeMillis()
                        ),
                        DOMAIN_NAME,
                        Set.of("COMPLIANCE", "IAM") 
                    );
                } catch (Exception e) {
                    log.warn("도구 실행 완료 정보 공유 실패: {}", e.getMessage());
                }
            }
        }
        
        return response;
    }

    private FilteringResult applyToolPolicyFiltering(ChatClientRequest request) {
        FilteringResult result = new FilteringResult();

        if (request.prompt().getOptions() instanceof ToolCallingChatOptions toolOptions) {
            List<ToolCallback> callbacks = toolOptions.getToolCallbacks();
            
            if (callbacks == null || callbacks.isEmpty()) {
                return result;
            }

            for (ToolCallback callback : callbacks) {
                String toolName = callback.getToolDefinition().name();
                SoarTool.RiskLevel riskLevel = policyManager.getRiskLevel(toolName);

                result.addToolRisk(toolName, riskLevel);

                if (policyManager.isBlocked(toolName)) {
                                        result.addFilteredTool(toolName);
                    
                    toolOptions.getToolCallbacks().remove(callback);
                } else {
                    result.addAllowedTool(toolName);

                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("riskLevel", riskLevel.name());
                    metadata.put("requiresApproval", policyManager.requiresApproval(toolName));
                    metadata.put("timeout", policyManager.getApprovalTimeout(toolName));
                    metadata.put("addedBy", "SoarPolicyAdvisor");
                    metadata.put("timestamp", System.currentTimeMillis());
                    
                    result.addToolMetadata(toolName, metadata);

                    if (riskLevel == SoarTool.RiskLevel.HIGH || 
                        riskLevel == SoarTool.RiskLevel.CRITICAL) {
                        result.addHighRiskTool(toolName);
                    }
                }
            }
        }
        
        return result;
    }

    private boolean checkRateLimit(ChatClientRequest request) {
        String userId = (String) request.context().get("user.id");

        Long lastCall = (Long) advisorContext.getAttribute("rateLimit." + userId);
        long currentTime = System.currentTimeMillis();
        
        if (lastCall != null) {
            long timeDiff = currentTime - lastCall;
            if (timeDiff < 1000) { 
                return false;
            }
        }
        
        advisorContext.setAttribute("rateLimit." + userId, currentTime);
        return true;
    }

    private boolean checkConcurrentExecutions(ChatClientRequest request) {
        Integer maxConcurrent = (Integer) domainConfig.get("max.concurrent.executions");
        if (maxConcurrent == null) {
            maxConcurrent = 10; 
        }
        
        Integer current = (Integer) advisorContext.getAttribute("concurrent.executions");
        if (current == null) {
            current = 0;
        }
        
        return current < maxConcurrent;
    }

    private static class HighRiskTool {
        final String name;
        final SoarTool.RiskLevel riskLevel;
        
        HighRiskTool(String name, SoarTool.RiskLevel riskLevel) {
            this.name = name;
            this.riskLevel = riskLevel;
        }
    }

    private static class ApprovalCheckResult {
        private final boolean approved;
        private final String reason;
        private final List<HighRiskTool> highRiskTools;
        
        private ApprovalCheckResult(boolean approved, String reason, List<HighRiskTool> tools) {
            this.approved = approved;
            this.reason = reason;
            this.highRiskTools = tools;
        }
        
        static ApprovalCheckResult approved() {
            return new ApprovalCheckResult(true, null, Collections.emptyList());
        }
        
        static ApprovalCheckResult approvedWithHighRiskTools(List<HighRiskTool> tools) {
            return new ApprovalCheckResult(true, null, tools);
        }
        
        static ApprovalCheckResult denied(String reason) {
            return new ApprovalCheckResult(false, reason, Collections.emptyList());
        }
        
        boolean isApproved() { return approved; }
        String getReason() { return reason; }
        boolean hasHighRiskTools() { return !highRiskTools.isEmpty(); }
        List<HighRiskTool> getHighRiskTools() { return highRiskTools; }
    }
}