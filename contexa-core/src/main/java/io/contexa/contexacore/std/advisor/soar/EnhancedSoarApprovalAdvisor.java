package io.contexa.contexacore.std.advisor.soar;

import io.opentelemetry.api.trace.Tracer;
import io.contexa.contexacore.std.advisor.core.DomainAdvisor;
import io.contexa.contexacore.std.advisor.core.AdvisorContext;
import io.contexa.contexacore.std.advisor.core.DomainPolicy;
import io.contexa.contexacore.std.advisor.core.SharedAdvisorContext;
import io.contexa.contexacore.soar.config.ToolApprovalPolicyManager;
import io.contexa.contexacore.dashboard.metrics.soar.ToolExecutionMetrics;
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

/**
 * SOAR 도구 정책 Advisor
 * 
 * SOAR 도구에 대한 정책 기반 필터링과 컨텍스트 관리를 담당합니다.
 * 승인 로직은 ApprovalAwareToolCallingManager에서 처리하므로,
 * 이 Advisor는 정책 검증과 메타데이터 관리에 집중합니다.
 * 
 * 주요 역할:
 * 1. 정책 기반 도구 필터링 (차단된 도구 제거)
 * 2. 도구 위험도 평가 및 컨텍스트 기록
 * 3. 감사 로그 및 메트릭 수집
 * 4. 도구 메타데이터 강화
 */
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
        
        // ApplicationContext로부터 의존성 가져오기
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
        // ApplicationContext가 설정되지 않은 경우 재시도
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
        
        // 의존성이 없으면 초기화 건너뛰기
        if (sharedContext == null) {
            log.warn("SharedAdvisorContext가 없어 초기화를 건너뜀");
            return;
        }
        
        // 도메인 컨텍스트 초기화
        AdvisorContext context = sharedContext.getDomainContext(DOMAIN_NAME);
        context.setAttribute("advisor.type", "tool-policy");
        context.setAttribute("initialized", LocalDateTime.now());
        context.setAttribute("filtering.enabled", true);
        
        // 설정 업데이트
        setEnabled(advisorEnabled);
        
        log.info("SOAR Tool Policy Advisor 초기화 완료 (order: {}, enabled: {})", 
            advisorOrder, advisorEnabled);
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
        
        // 차단 도구 목록 (예시)
        policyConfig.put("blocked.tools", List.of("system_shutdown", "data_delete_all"));
        
        // 최소 권한 레벨
        policyConfig.put("min.role.level", "OPERATOR");
        
        return new SoarDomainPolicy(policyConfig, true);
    }
    
    @Override
    protected boolean validateDomainRequest(ChatClientRequest request) {
        // SecurityContextAdvisor가 설정한 값 확인
        String sessionId = (String) request.context().get("session.id");
        String userId = (String) request.context().get("user.id");
        Boolean authenticated = (Boolean) request.context().get("authenticated");
        
        // 컨텍스트 정보 로그
        log.debug("SOAR 도메인 요청 검증 - sessionId: {}, userId: {}, authenticated: {}", 
            sessionId, userId, authenticated);
        
        // 개발 환경 확인
        if (!isProductionEnvironment()) {
            // 개발 환경에서는 경고만 출력하고 통과
            if (sessionId == null || userId == null) {
                log.debug("개발 환경 - 보안 컨텍스트 누락 허용 (sessionId: {}, userId: {})", 
                    sessionId, userId);
            }
            return true;
        }
        
        // 프로덕션 환경에서의 검증
        if (sessionId == null || sessionId.isEmpty()) {
            log.warn("프로덕션 환경 - 세션 ID 누락");
            return false;
        }
        
        if (userId == null || userId.isEmpty()) {
            log.warn("프로덕션 환경 - 사용자 ID 누락");
            return false;
        }
        
        // anonymous 사용자에 대한 정책 (선택적)
        if ("anonymous".equals(userId)) {
            log.info("익명 사용자 요청 감지 - 정책에 따라 처리");
            // 설정에 따라 익명 사용자 허용/거부
            // 현재는 허용
            return true;
        }
        
        return true;
    }
    
    /**
     * 프로덕션 환경인지 확인
     */
    private boolean isProductionEnvironment() {
        String profile = System.getProperty("spring.profiles.active", "dev");
        return "prod".equals(profile) || "production".equals(profile);
    }
    
    @Override
    protected boolean performSecurityCheck(ChatClientRequest request) {
        // SOAR 보안 체크
        
        // 1. Rate limiting 체크
        if (!checkRateLimit(request)) {
            log.warn("Rate limit exceeded");
            return false;
        }
        
        // 2. 동시 실행 제한 체크
        if (!checkConcurrentExecutions(request)) {
            log.warn("Concurrent execution limit exceeded");
            return false;
        }
        
        return true;
    }
    
    @Override
    protected ChatClientRequest beforeCall(ChatClientRequest request) {
        // 부모 클래스 처리
        request = super.beforeCall(request);
        
        log.debug("SOAR Tool Policy Advisor - 도구 정책 검사 시작");
        
        // 의존성이 없으면 필터링 건너뛰기
        if (policyManager == null) {
            log.warn("ToolApprovalPolicyManager가 없어 필터링을 건너뜀");
            return request;
        }
        
        // 도구 정책 필터링 및 메타데이터 추가
        FilteringResult filteringResult = applyToolPolicyFiltering(request);
        
        // 필터링 결과를 컨텍스트에 저장
        request.context().put(ALLOWED_TOOLS_KEY, filteringResult.getAllowedTools());
        request.context().put(FILTERED_TOOLS_KEY, filteringResult.getFilteredTools());
        request.context().put(TOOL_RISK_KEY, filteringResult.getToolRiskMap());
        request.context().put(TOOL_METADATA_KEY, filteringResult.getToolMetadata());
        
        // 위험도 정보를 다른 도메인과 공유
        if (!filteringResult.getHighRiskTools().isEmpty() && sharedContext != null) {
            log.info("고위험 도구 감지: {}", filteringResult.getHighRiskTools());
            try {
                sharedContext.shareAcrossDomains(
                    "tool.high_risk.detected",
                    filteringResult.getHighRiskTools(),
                    DOMAIN_NAME,
                    Set.of("IAM", "COMPLIANCE") // IAM과 Compliance 도메인과 공유
                );
            } catch (Exception e) {
                log.warn("도메인 간 정보 공유 실패: {}", e.getMessage());
            }
        }
        
        // 차단된 도구가 있으면 로그 및 메트릭 기록
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
        
        // 허용된 도구 메트릭
        for (String toolName : filteringResult.getAllowedTools()) {
            recordMetric("soar.tool.allowed", 1);
        }
        
        return request;
    }
    
    @Override
    protected ChatClientResponse afterCall(ChatClientResponse response, ChatClientRequest request) {
        // 부모 클래스 처리
        response = super.afterCall(response, request);
        
        // 실행 완료 정보를 다른 도메인과 공유
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
                        Set.of("COMPLIANCE", "IAM") // 특정 도메인과만 공유
                    );
                } catch (Exception e) {
                    log.warn("도구 실행 완료 정보 공유 실패: {}", e.getMessage());
                }
            }
        }
        
        return response;
    }
    
    /**
     * 도구 정책 필터링 적용
     * 
     * 정책에 따라 도구를 필터링하고 메타데이터를 추가합니다.
     * 승인 요청은 하지 않고, ApprovalAwareToolCallingManager에서 처리합니다.
     */
    private FilteringResult applyToolPolicyFiltering(ChatClientRequest request) {
        FilteringResult result = new FilteringResult();
        
        // ChatOptions에서 도구 정보 추출
        if (request.prompt().getOptions() instanceof ToolCallingChatOptions toolOptions) {
            List<ToolCallback> callbacks = toolOptions.getToolCallbacks();
            
            if (callbacks == null || callbacks.isEmpty()) {
                return result;
            }
            
            // 각 도구에 대해 정책 검사
            for (ToolCallback callback : callbacks) {
                String toolName = callback.getToolDefinition().name();
                SoarTool.RiskLevel riskLevel = policyManager.getRiskLevel(toolName);
                
                // 위험도 기록
                result.addToolRisk(toolName, riskLevel);
                
                // 정책에 따라 필터링
                if (policyManager.isBlocked(toolName)) {
                    log.debug("도구 차단됨: {} (정책: BLOCKED)", toolName);
                    result.addFilteredTool(toolName);
                    // 차단된 도구는 ChatOptions 에서 제거
                    toolOptions.getToolCallbacks().remove(callback);
                } else {
                    result.addAllowedTool(toolName);
                    
                    // 메타데이터 추가
                    Map<String, Object> metadata = new HashMap<>();
                    metadata.put("riskLevel", riskLevel.name());
                    metadata.put("requiresApproval", policyManager.requiresApproval(toolName));
                    metadata.put("timeout", policyManager.getApprovalTimeout(toolName));
                    metadata.put("addedBy", "SoarPolicyAdvisor");
                    metadata.put("timestamp", System.currentTimeMillis());
                    
                    result.addToolMetadata(toolName, metadata);
                    
                    // 고위험 도구 표시
                    if (riskLevel == SoarTool.RiskLevel.HIGH || 
                        riskLevel == SoarTool.RiskLevel.CRITICAL) {
                        result.addHighRiskTool(toolName);
                    }
                }
            }
        }
        
        return result;
    }
    
    
    
    /**
     * Rate limiting 체크
     */
    private boolean checkRateLimit(ChatClientRequest request) {
        String userId = (String) request.context().get("user.id");
        
        // 도메인 컨텍스트에서 rate limit 정보 확인
        Long lastCall = (Long) advisorContext.getAttribute("rateLimit." + userId);
        long currentTime = System.currentTimeMillis();
        
        if (lastCall != null) {
            long timeDiff = currentTime - lastCall;
            if (timeDiff < 1000) { // 1초 이내 재호출 방지
                return false;
            }
        }
        
        advisorContext.setAttribute("rateLimit." + userId, currentTime);
        return true;
    }
    
    /**
     * 동시 실행 제한 체크
     */
    private boolean checkConcurrentExecutions(ChatClientRequest request) {
        Integer maxConcurrent = (Integer) domainConfig.get("max.concurrent.executions");
        if (maxConcurrent == null) {
            maxConcurrent = 10; // 기본값
        }
        
        Integer current = (Integer) advisorContext.getAttribute("concurrent.executions");
        if (current == null) {
            current = 0;
        }
        
        return current < maxConcurrent;
    }
    
    /**
     * 고위험 도구 정보
     */
    private static class HighRiskTool {
        final String name;
        final SoarTool.RiskLevel riskLevel;
        
        HighRiskTool(String name, SoarTool.RiskLevel riskLevel) {
            this.name = name;
            this.riskLevel = riskLevel;
        }
    }
    
    /**
     * 승인 체크 결과
     */
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