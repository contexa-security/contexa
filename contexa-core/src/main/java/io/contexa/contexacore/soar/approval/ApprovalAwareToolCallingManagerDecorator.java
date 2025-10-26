package io.contexa.contexacore.soar.approval;

import io.contexa.contexacore.soar.config.ToolApprovalPolicyManager;
import io.contexa.contexacore.dashboard.metrics.soar.ToolExecutionMetrics;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarExecutionMode;
import io.contexa.contexacore.domain.entity.ToolExecutionContext;
import io.contexa.contexacore.repository.ToolExecutionContextRepository;
import io.contexa.contexacommon.annotation.SoarTool;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.DefaultToolCallingManager;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.model.tool.ToolExecutionResult;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.simp.SimpMessagingTemplate;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

/**
 * Approval-Aware Tool Calling Manager Decorator
 * 
 * Spring AI의 DefaultToolCallingManager를 Decorator 패턴으로 래핑하여
 * 고위험 도구 실행 시 승인 메커니즘을 추가합니다.
 * 
 * SOLID 원칙 준수:
 * - Single Responsibility: 오직 승인 로직만 담당
 * - Open/Closed: DefaultToolCallingManager 확장 가능
 * - Liskov Substitution: ToolCallingManager 인터페이스 완벽 구현
 * - Dependency Inversion: 인터페이스에 의존
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class ApprovalAwareToolCallingManagerDecorator implements ToolCallingManager {
    
    // 위임할 실제 ToolCallingManager (Spring AI 표준)
    private final DefaultToolCallingManager delegate;
    
    // 승인 관련 서비스
    private final UnifiedApprovalService approvalService;
    private final ToolApprovalPolicyManager policyManager;
    private final ToolExecutionMetrics executionMetrics;
    private final McpApprovalNotificationService notificationService;
    
    // 비동기 모드 지원을 위한 추가 의존성
    private final ToolExecutionContextRepository contextRepository;
    private final AsyncToolExecutionService asyncExecutionService;
    private final ObjectMapper objectMapper;
    
    // 현재 SoarContext를 저장하기 위한 ThreadLocal
    private final ThreadLocal<SoarContext> currentContext = new ThreadLocal<>();
    
    // 승인 대기 중인 요청 추적
    private final Map<String, CompletableFuture<Boolean>> pendingApprovals = new ConcurrentHashMap<>();
    
    // 승인 타임아웃 설정 (초)
    private static final long APPROVAL_TIMEOUT_SECONDS = 300; // 5분
    
    /**
     * 도구 정의 해결 - DefaultToolCallingManager에 위임
     */
    @Override
    public List<ToolDefinition> resolveToolDefinitions(ToolCallingChatOptions toolCallingChatOptions) {
        return delegate.resolveToolDefinitions(toolCallingChatOptions);
    }
    
    /**
     * 도구 실행 - 승인 로직 추가 후 DefaultToolCallingManager에 위임
     * 
     * 이것이 핵심 메서드입니다. 고위험 도구를 감지하고 승인을 처리한 후
     * 실제 실행은 DefaultToolCallingManager에 위임합니다.
     * 
     * 동기/비동기 모드 지원:
     * - SYNC: 기존대로 CompletableFuture.get()으로 블로킹 대기
     * - ASYNC: DB에 저장하고 즉시 PENDING 결과 반환
     */
    @Override
    public ToolExecutionResult executeToolCalls(Prompt prompt, ChatResponse chatResponse) {
        long startTime = System.currentTimeMillis();
        String requestId = UUID.randomUUID().toString();
        
        try {
            log.debug("승인 검사 시작 (요청 ID: {})", requestId);
            
            // 0. 현재 실행 모드 확인
            SoarExecutionMode executionMode = getExecutionMode();
            log.debug("실행 모드: {}", executionMode);
            
            // 1. 도구 호출 정보 추출
            List<ToolCallInfo> toolCalls = extractToolCalls(chatResponse);
            
            if (toolCalls.isEmpty()) {
                log.debug("도구 호출이 없음 - 바로 위임");
                return delegate.executeToolCalls(prompt, chatResponse);
            }
            
            // 2. 고위험 도구 식별
            List<ToolCallInfo> highRiskTools = identifyHighRiskTools(toolCalls, prompt.getOptions());
            
            if (!highRiskTools.isEmpty()) {
                log.warn("고위험 도구 감지: {} 개", highRiskTools.size());
                logHighRiskTools(highRiskTools);
                
                // 3. 실행 모드에 따라 분기 처리
                if (executionMode == SoarExecutionMode.ASYNC) {
                    // 비동기 모드: DB에 저장하고 즉시 반환
                    return handleAsyncApproval(requestId, highRiskTools, toolCalls, prompt, chatResponse);
                } else {
                    // 동기 모드: 기존대로 블로킹 대기
                    boolean approved = requestAndWaitForApproval(
                        requestId,
                        highRiskTools,
                        prompt.getOptions()
                    );
                    
                    if (!approved) {
                        // 4. 승인 거부 시 거부 결과 반환
                        log.warn("도구 실행 거부됨 (요청 ID: {})", requestId);
                        return createDenialResult(toolCalls, prompt, chatResponse);
                    }
                    
                    log.info("도구 실행 승인됨 (요청 ID: {})", requestId);
                }
            } else {
                log.debug("✓ 모든 도구가 저위험 - 승인 불필요");
            }
            
            // 5. 승인된 경우 (또는 저위험인 경우) DefaultToolCallingManager에 실행 위임
            log.debug("DefaultToolCallingManager에 실행 위임");
            ToolExecutionResult result = delegate.executeToolCalls(prompt, chatResponse);
            
            // 6. 실행 메트릭 기록
            recordExecutionMetrics(requestId, toolCalls, startTime, true);
            
            // 7. 실행 완료 알림
            notifyExecutionComplete(requestId, toolCalls, result);
            
            return result;
            
        } catch (Exception e) {
            log.error("도구 실행 중 오류 발생 (요청 ID: {})", requestId, e);
            recordExecutionMetrics(requestId, Collections.emptyList(), startTime, false);
            notificationService.sendExecutionFailed(requestId, e);
            throw new RuntimeException("Tool execution failed", e);
        }
    }
    
    /**
     * ChatResponse에서 도구 호출 정보 추출
     */
    private List<ToolCallInfo> extractToolCalls(ChatResponse chatResponse) {
        List<ToolCallInfo> toolCalls = new ArrayList<>();
        
        if (chatResponse == null || chatResponse.getResults() == null) {
            return toolCalls;
        }
        
        for (Generation generation : chatResponse.getResults()) {
            AssistantMessage message = generation.getOutput();
            
            if (message != null && message.getToolCalls() != null) {
                message.getToolCalls().forEach(toolCall -> {
                    toolCalls.add(new ToolCallInfo(
                        toolCall.id(),
                        toolCall.name(),
                        toolCall.type(),
                        toolCall.arguments()
                    ));
                });
            }
        }
        
        if (!toolCalls.isEmpty()) {
            log.info("{} 개의 도구 호출 감지됨", toolCalls.size());
        }
        
        return toolCalls;
    }
    
    /**
     * 고위험 도구 식별
     */
    private List<ToolCallInfo> identifyHighRiskTools(List<ToolCallInfo> toolCalls, ChatOptions chatOptions) {
        List<ToolCallInfo> highRiskTools = new ArrayList<>();
        
        for (ToolCallInfo toolCall : toolCalls) {
            // 정책 관리자를 통해 위험도 확인
            SoarTool.RiskLevel riskLevel = policyManager.getRiskLevel(toolCall.name);
            
            // 메타데이터에서 추가 위험도 정보 확인
            if (chatOptions instanceof ToolCallingChatOptions toolCallingOptions) {
                riskLevel = checkToolRiskFromOptions(toolCall.name, toolCallingOptions, riskLevel);
            }
            
            if (isHighRisk(riskLevel)) {
                highRiskTools.add(toolCall);
                log.debug("고위험 도구: {} (위험도: {})", toolCall.name, riskLevel);
            }
        }
        
        return highRiskTools;
    }
    
    /**
     * ChatOptions에서 도구 위험도 확인
     */
    private SoarTool.RiskLevel checkToolRiskFromOptions(
            String toolName,
            ToolCallingChatOptions options,
            SoarTool.RiskLevel currentLevel) {
        
        List<ToolCallback> callbacks = options.getToolCallbacks();
        if (callbacks == null || callbacks.isEmpty()) {
            return currentLevel;
        }
        
        for (ToolCallback callback : callbacks) {
            if (callback.getToolDefinition().name().equals(toolName)) {
                // Spring AI의 ToolDefinition은 metadata() 메서드를 제공하지 않음
                // 도구 이름으로 위험도 판단
                if (isHighRiskToolByName(toolName)) {
                    return SoarTool.RiskLevel.HIGH;
                }
            }
        }
        
        return currentLevel;
    }
    
    /**
     * 고위험 여부 판단
     */
    private boolean isHighRisk(SoarTool.RiskLevel riskLevel) {
        return riskLevel == SoarTool.RiskLevel.HIGH || 
               riskLevel == SoarTool.RiskLevel.CRITICAL;
    }
    
    /**
     * 승인 요청 및 대기
     */
    private boolean requestAndWaitForApproval(
            String requestId,
            List<ToolCallInfo> highRiskTools,
            ChatOptions chatOptions) {
        
        try {
            // 승인 요청 생성
            ApprovalRequest approvalRequest = buildApprovalRequest(requestId, highRiskTools);
            
            // 알림 전송
            notificationService.sendApprovalRequest(approvalRequest);
            
            // 비동기 승인 요청 - approvalService가 이미 CompletableFuture를 반환
            CompletableFuture<Boolean> approvalFuture = approvalService.requestApproval(approvalRequest);
            
            // 승인 추적
            pendingApprovals.put(requestId, approvalFuture);
            
            // 타임아웃과 함께 결과 대기
            boolean approved = approvalFuture.get(APPROVAL_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            
            // 추적 제거
            pendingApprovals.remove(requestId);

            return approved;
            
        } catch (TimeoutException e) {
            log.warn("승인 타임아웃 ({}초 경과)", APPROVAL_TIMEOUT_SECONDS);
            pendingApprovals.remove(requestId);
            return false;
        } catch (Exception e) {
            log.error("승인 처리 중 오류", e);
            pendingApprovals.remove(requestId);
            return false;
        }
    }
    
    /**
     * 승인 요청 생성
     */
    private ApprovalRequest buildApprovalRequest(String requestId, List<ToolCallInfo> tools) {
        SoarTool.RiskLevel soarRiskLevel = determineMaxRiskLevel(tools);
        
        return ApprovalRequest.builder()
            .requestId(requestId)
            .requestedAt(LocalDateTime.now())
            .requestedBy("AI System")
            .toolName(tools.stream().map(t -> t.name).collect(Collectors.joining(", ")))
            .riskLevel(convertToApprovalRiskLevel(soarRiskLevel))
            .reason("고위험 도구 실행 승인 필요")
            .status(ApprovalRequest.ApprovalStatus.PENDING)
            .context(Map.of(
                "toolCount", tools.size(),
                "toolDetails", tools,
                "timestamp", System.currentTimeMillis()
            ))
            .build();
    }
    
    /**
     * SoarTool.RiskLevel을 ApprovalRequest.RiskLevel로 변환
     */
    private ApprovalRequest.RiskLevel convertToApprovalRiskLevel(SoarTool.RiskLevel soarRiskLevel) {
        return switch (soarRiskLevel) {
            case CRITICAL -> ApprovalRequest.RiskLevel.CRITICAL;
            case HIGH -> ApprovalRequest.RiskLevel.HIGH;
            case MEDIUM -> ApprovalRequest.RiskLevel.MEDIUM;
            case LOW -> ApprovalRequest.RiskLevel.LOW;
            default -> ApprovalRequest.RiskLevel.INFO;
        };
    }
    
    /**
     * 도구 이름으로 위험도 판단
     */
    private boolean isHighRiskToolByName(String toolName) {
        // 고위험 도구 패턴
        return toolName.contains("delete") ||
               toolName.contains("remove") ||
               toolName.contains("drop") ||
               toolName.contains("execute") ||
               toolName.contains("admin") ||
               toolName.contains("security") ||
               toolName.contains("system");
    }
    
    /**
     * 최대 위험도 결정
     */
    private SoarTool.RiskLevel determineMaxRiskLevel(List<ToolCallInfo> tools) {
        return tools.stream()
            .map(tool -> policyManager.getRiskLevel(tool.name))
            .max(Comparator.comparingInt(Enum::ordinal))
            .orElse(SoarTool.RiskLevel.LOW);
    }
    
    /**
     * 거부 결과 생성
     */
    private ToolExecutionResult createDenialResult(
            List<ToolCallInfo> toolCalls,
            Prompt prompt,
            ChatResponse chatResponse) {
        
        // 거부 메시지 생성
        String denialMessage = String.format(
            "도구 실행이 거부되었습니다. 고위험 도구 실행에는 승인이 필요합니다. " +
            "거부된 도구: %s",
            toolCalls.stream().map(t -> t.name).collect(Collectors.joining(", "))
        );
        
        // AssistantMessage 생성
        AssistantMessage denialAssistantMessage = new AssistantMessage(denialMessage);
        
        // ConversationHistory 구성
        List<org.springframework.ai.chat.messages.Message> conversationHistory = new ArrayList<>();
        conversationHistory.addAll(prompt.getInstructions());
        conversationHistory.add(denialAssistantMessage);
        
        // 거부 결과 반환
        return ToolExecutionResult.builder()
            .conversationHistory(conversationHistory)
            .returnDirect(true)  // 직접 반환
            .build();
    }
    
    /**
     * 고위험 도구 로깅
     */
    private void logHighRiskTools(List<ToolCallInfo> highRiskTools) {
        log.warn("========== 고위험 도구 감지 ==========");
        for (ToolCallInfo tool : highRiskTools) {
            SoarTool.RiskLevel risk = policyManager.getRiskLevel(tool.name);
            log.warn("  {} (위험도: {})", tool.name, risk);
        }
        log.warn("=====================================");
    }
    
    /**
     * 실행 메트릭 기록
     */
    private void recordExecutionMetrics(
            String requestId,
            List<ToolCallInfo> toolCalls,
            long startTime,
            boolean success) {
        
        long duration = System.currentTimeMillis() - startTime;
        
        // 메트릭 기록 - 각 도구에 대해 개별적으로 기록
        for (ToolCallInfo tool : toolCalls) {
            executionMetrics.recordExecution(
                tool.name,
                duration,
                success
            );

            // EventRecorder 인터페이스를 통한 이벤트 기록
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("tool", tool.name);
            metadata.put("duration", duration * 1_000_000); // ms to ns
            metadata.put("success", success);
            metadata.put("request_id", requestId);

            String eventType = success ? "execution_success" : "execution_failure";
            executionMetrics.recordEvent(eventType, metadata);
        }
        
        if (log.isDebugEnabled()) {
            log.debug("실행 메트릭 - 요청: {}, 도구: {}, 소요시간: {}ms, 성공: {}",
                     requestId, toolCalls.size(), duration, success);
        }
    }
    
    /**
     * 실행 완료 알림
     */
    private void notifyExecutionComplete(
            String requestId,
            List<ToolCallInfo> toolCalls,
            ToolExecutionResult result) {
        
        String toolNames = toolCalls.stream()
            .map(t -> t.name)
            .collect(Collectors.joining(", "));
        
        notificationService.sendExecutionCompleted(
            requestId + ": " + toolNames,
            result.conversationHistory(),
            System.currentTimeMillis()
        );
    }
    
    /**
     * 도구 호출 정보 내부 클래스
     */
    private static class ToolCallInfo {
        final String id;
        final String name;
        final String type;
        final String arguments;
        
        ToolCallInfo(String id, String name, String type, String arguments) {
            this.id = id;
            this.name = name;
            this.type = type;
            this.arguments = arguments;
        }
    }
    
    /**
     * 현재 대기 중인 승인 요청 수 반환
     */
    public int getPendingApprovalsCount() {
        return pendingApprovals.size();
    }
    
    /**
     * 모든 대기 중인 승인 취소
     */
    public void cancelAllPendingApprovals() {
        log.warn("모든 대기 중인 승인 취소: {} 개", pendingApprovals.size());
        pendingApprovals.forEach((id, future) -> future.cancel(true));
        pendingApprovals.clear();
    }
    
    /**
     * 현재 SoarContext 설정
     * SoarLab이나 다른 컴포넌트에서 실행 모드를 설정하기 위해 사용
     */
    public void setCurrentContext(SoarContext context) {
        currentContext.set(context);
    }
    
    /**
     * 현재 SoarContext 제거
     */
    public void clearCurrentContext() {
        currentContext.remove();
    }
    
    /**
     * 실행 모드 결정
     * ThreadLocal의 SoarContext에서 가져오거나 기본값 사용
     */
    private SoarExecutionMode getExecutionMode() {
        SoarContext context = currentContext.get();
        if (context != null && context.getExecutionMode() != null) {
            SoarExecutionMode mode = context.getExecutionMode();
            
            // AUTO 모드인 경우 동적 결정
            if (mode == SoarExecutionMode.AUTO) {
                // WebSocket/SSE 연결 가능 여부 또는 다른 조건으로 자동 결정
                // 여기서는 간단히 ASYNC를 기본으로 설정
                return SoarExecutionMode.ASYNC;
            }
            
            return mode;
        }
        
        // 기본값: 동기 모드 (기존 동작 유지)
        return SoarExecutionMode.SYNC;
    }
    
    /**
     * 비동기 승인 처리
     * DB에 도구 실행 컨텍스트를 저장하고 PENDING 결과 반환
     */
    private ToolExecutionResult handleAsyncApproval(
            String requestId,
            List<ToolCallInfo> highRiskTools,
            List<ToolCallInfo> allToolCalls,
            Prompt prompt,
            ChatResponse chatResponse) {
        
        try {
            log.info("비동기 모드: 도구 실행 컨텍스트를 DB에 저장 (요청 ID: {})", requestId);
            
            // 1. 승인 요청 생성
            ApprovalRequest approvalRequest = buildApprovalRequest(requestId, highRiskTools);
            
            // 2. 도구 실행 컨텍스트 저장
            ToolExecutionContext executionContext = saveToolExecutionContext(
                requestId,
                highRiskTools.get(0), // 첫 번째 고위험 도구 정보 사용
                prompt,
                chatResponse
            );
            
            // 3. 승인 알림 전송 (DB 저장 모드)
            notificationService.sendAsyncApprovalRequest(approvalRequest, executionContext);
            
            // 4. 비동기 승인 요청 등록 (나중에 승인 처리를 위해)
            approvalService.registerAsyncApproval(approvalRequest, executionContext);
            
            // 5. PENDING 결과 반환
            String pendingMessage = String.format(
                "도구 실행 승인 대기 중입니다. (요청 ID: %s)\n" +
                "고위험 도구: %s\n" +
                "승인 후 자동으로 실행됩니다.",
                requestId,
                highRiskTools.stream().map(t -> t.name).collect(Collectors.joining(", "))
            );
            
            AssistantMessage pendingAssistantMessage = new AssistantMessage(pendingMessage);
            
            List<org.springframework.ai.chat.messages.Message> conversationHistory = new ArrayList<>();
            conversationHistory.addAll(prompt.getInstructions());
            conversationHistory.add(pendingAssistantMessage);
            
            return ToolExecutionResult.builder()
                .conversationHistory(conversationHistory)
                .returnDirect(false) // 계속 처리 가능
                .build();
            
        } catch (Exception e) {
            log.error("비동기 승인 처리 중 오류 (요청 ID: {})", requestId, e);
            // 오류 발생 시 동기 모드로 폴백
            return requestAndWaitForApprovalSync(requestId, highRiskTools, prompt, chatResponse);
        }
    }
    
    /**
     * 도구 실행 컨텍스트를 DB에 저장
     */
    private ToolExecutionContext saveToolExecutionContext(
            String requestId,
            ToolCallInfo toolCall,
            Prompt prompt,
            ChatResponse chatResponse) throws Exception {
        
        SoarContext soarContext = currentContext.get();
        
        // Prompt 직렬화
        List<Map<String, String>> promptData = new ArrayList<>();
        for (org.springframework.ai.chat.messages.Message msg : prompt.getInstructions()) {
            Map<String, String> msgData = new HashMap<>();
            msgData.put("role", msg.getMessageType().name().toLowerCase());
            msgData.put("content", msg.getText());
            promptData.add(msgData);
        }
        String promptJson = objectMapper.writeValueAsString(promptData);
        
        // ChatOptions 직렬화
        String chatOptionsJson = null;
        if (prompt.getOptions() != null) {
            Map<String, Object> optionsData = new HashMap<>();
            if (prompt.getOptions() instanceof ToolCallingChatOptions toolOptions) {
                optionsData.put("toolNames", toolOptions.getToolNames());
                optionsData.put("internalToolExecutionEnabled",
                        ToolCallingChatOptions.isInternalToolExecutionEnabled(prompt.getOptions()));
            }
            chatOptionsJson = objectMapper.writeValueAsString(optionsData);
        }
        
        // ChatResponse 직렬화 (간단한 버전)
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("toolCallId", toolCall.id);
        responseData.put("toolName", toolCall.name);
        responseData.put("arguments", toolCall.arguments);
        String responseJson = objectMapper.writeValueAsString(responseData);
        
        // ToolExecutionContext 생성 및 저장
        ToolExecutionContext context = ToolExecutionContext.builder()
            .requestId(requestId)
            .incidentId(soarContext != null ? soarContext.getIncidentId() : null)
            .sessionId(soarContext != null ? soarContext.getSessionId() : null)
            .toolName(toolCall.name)
            .toolType("SOAR")
            .toolCallId(toolCall.id)
            .toolArguments(toolCall.arguments)
            .promptContent(promptJson)
            .chatOptions(chatOptionsJson)
            .chatResponse(responseJson)
            .status("PENDING")
            .riskLevel(policyManager.getRiskLevel(toolCall.name).name())
            .expiresAt(LocalDateTime.now().plusMinutes(30)) // 30분 후 만료
            .build();
        
        return contextRepository.save(context);
    }
    
    /**
     * 동기 모드 폴백 처리
     */
    private ToolExecutionResult requestAndWaitForApprovalSync(
            String requestId,
            List<ToolCallInfo> highRiskTools,
            Prompt prompt,
            ChatResponse chatResponse) {
        
        boolean approved = requestAndWaitForApproval(
            requestId,
            highRiskTools,
            prompt.getOptions()
        );
        
        if (!approved) {
            log.warn("도구 실행 거부됨 (요청 ID: {})", requestId);
            return createDenialResult(highRiskTools, prompt, chatResponse);
        }
        
        log.info("도구 실행 승인됨 (요청 ID: {})", requestId);
        
        // 승인된 경우 도구 실행
        return delegate.executeToolCalls(prompt, chatResponse);
    }
}