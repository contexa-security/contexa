package io.contexa.contexacoreenterprise.soar.approval;

import io.contexa.contexacoreenterprise.soar.config.ToolApprovalPolicyManager;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarExecutionMode;
import io.contexa.contexacommon.annotation.SoarTool;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository;
import io.contexa.contexacoreenterprise.dashboard.metrics.soar.ToolExecutionMetrics;
import io.contexa.contexacoreenterprise.domain.entity.ToolExecutionContext;
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


@Slf4j
@RequiredArgsConstructor
public class ApprovalAwareToolCallingManagerDecorator implements ToolCallingManager {
    
    
    private final DefaultToolCallingManager delegate;
    
    
    private final UnifiedApprovalService approvalService;
    private final ToolApprovalPolicyManager policyManager;
    private final ToolExecutionMetrics executionMetrics;
    private final McpApprovalNotificationService notificationService;
    
    
    private final ToolExecutionContextRepository contextRepository;
    private final AsyncToolExecutionService asyncExecutionService;
    private final ObjectMapper objectMapper;
    
    
    private final ThreadLocal<SoarContext> currentContext = new ThreadLocal<>();
    
    
    private final Map<String, CompletableFuture<Boolean>> pendingApprovals = new ConcurrentHashMap<>();
    
    
    private static final long APPROVAL_TIMEOUT_SECONDS = 300; 
    
    
    @Override
    public List<ToolDefinition> resolveToolDefinitions(ToolCallingChatOptions toolCallingChatOptions) {
        return delegate.resolveToolDefinitions(toolCallingChatOptions);
    }
    
    
    @Override
    public ToolExecutionResult executeToolCalls(Prompt prompt, ChatResponse chatResponse) {
        long startTime = System.currentTimeMillis();
        String requestId = UUID.randomUUID().toString();
        
        try {
            log.debug("승인 검사 시작 (요청 ID: {})", requestId);
            
            
            SoarExecutionMode executionMode = getExecutionMode();
            log.debug("실행 모드: {}", executionMode);
            
            
            List<ToolCallInfo> toolCalls = extractToolCalls(chatResponse);
            
            if (toolCalls.isEmpty()) {
                log.debug("도구 호출이 없음 - 바로 위임");
                return delegate.executeToolCalls(prompt, chatResponse);
            }
            
            
            List<ToolCallInfo> highRiskTools = identifyHighRiskTools(toolCalls, prompt.getOptions());
            
            if (!highRiskTools.isEmpty()) {
                log.warn("고위험 도구 감지: {} 개", highRiskTools.size());
                logHighRiskTools(highRiskTools);
                
                
                if (executionMode == SoarExecutionMode.ASYNC) {
                    
                    return handleAsyncApproval(requestId, highRiskTools, toolCalls, prompt, chatResponse);
                } else {
                    
                    boolean approved = requestAndWaitForApproval(
                        requestId,
                        highRiskTools,
                        prompt.getOptions()
                    );
                    
                    if (!approved) {
                        
                        log.warn("도구 실행 거부됨 (요청 ID: {})", requestId);
                        return createDenialResult(toolCalls, prompt, chatResponse);
                    }
                    
                    log.info("도구 실행 승인됨 (요청 ID: {})", requestId);
                }
            } else {
                log.debug("✓ 모든 도구가 저위험 - 승인 불필요");
            }
            
            
            log.debug("DefaultToolCallingManager에 실행 위임");
            ToolExecutionResult result = delegate.executeToolCalls(prompt, chatResponse);
            
            
            recordExecutionMetrics(requestId, toolCalls, startTime, true);
            
            
            notifyExecutionComplete(requestId, toolCalls, result);
            
            return result;
            
        } catch (Exception e) {
            log.error("도구 실행 중 오류 발생 (요청 ID: {})", requestId, e);
            recordExecutionMetrics(requestId, Collections.emptyList(), startTime, false);
            notificationService.sendExecutionFailed(requestId, e);
            throw new RuntimeException("Tool execution failed", e);
        }
    }
    
    
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
    
    
    private List<ToolCallInfo> identifyHighRiskTools(List<ToolCallInfo> toolCalls, ChatOptions chatOptions) {
        List<ToolCallInfo> highRiskTools = new ArrayList<>();
        
        for (ToolCallInfo toolCall : toolCalls) {
            
            SoarTool.RiskLevel riskLevel = policyManager.getRiskLevel(toolCall.name);
            
            
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
                
                
                if (isHighRiskToolByName(toolName)) {
                    return SoarTool.RiskLevel.HIGH;
                }
            }
        }
        
        return currentLevel;
    }
    
    
    private boolean isHighRisk(SoarTool.RiskLevel riskLevel) {
        return riskLevel == SoarTool.RiskLevel.HIGH || 
               riskLevel == SoarTool.RiskLevel.CRITICAL;
    }
    
    
    private boolean requestAndWaitForApproval(
            String requestId,
            List<ToolCallInfo> highRiskTools,
            ChatOptions chatOptions) {
        
        try {
            
            ApprovalRequest approvalRequest = buildApprovalRequest(requestId, highRiskTools);
            
            
            notificationService.sendApprovalRequest(approvalRequest);
            
            
            CompletableFuture<Boolean> approvalFuture = approvalService.requestApproval(approvalRequest);
            
            
            pendingApprovals.put(requestId, approvalFuture);
            
            
            boolean approved = approvalFuture.get(APPROVAL_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            
            
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
    
    
    private ApprovalRequest.RiskLevel convertToApprovalRiskLevel(SoarTool.RiskLevel soarRiskLevel) {
        return switch (soarRiskLevel) {
            case CRITICAL -> ApprovalRequest.RiskLevel.CRITICAL;
            case HIGH -> ApprovalRequest.RiskLevel.HIGH;
            case MEDIUM -> ApprovalRequest.RiskLevel.MEDIUM;
            case LOW -> ApprovalRequest.RiskLevel.LOW;
            default -> ApprovalRequest.RiskLevel.INFO;
        };
    }
    
    
    private boolean isHighRiskToolByName(String toolName) {
        
        return toolName.contains("delete") ||
               toolName.contains("remove") ||
               toolName.contains("drop") ||
               toolName.contains("execute") ||
               toolName.contains("admin") ||
               toolName.contains("security") ||
               toolName.contains("system");
    }
    
    
    private SoarTool.RiskLevel determineMaxRiskLevel(List<ToolCallInfo> tools) {
        return tools.stream()
            .map(tool -> policyManager.getRiskLevel(tool.name))
            .max(Comparator.comparingInt(Enum::ordinal))
            .orElse(SoarTool.RiskLevel.LOW);
    }
    
    
    private ToolExecutionResult createDenialResult(
            List<ToolCallInfo> toolCalls,
            Prompt prompt,
            ChatResponse chatResponse) {
        
        
        String denialMessage = String.format(
            "도구 실행이 거부되었습니다. 고위험 도구 실행에는 승인이 필요합니다. " +
            "거부된 도구: %s",
            toolCalls.stream().map(t -> t.name).collect(Collectors.joining(", "))
        );
        
        
        AssistantMessage denialAssistantMessage = new AssistantMessage(denialMessage);
        
        
        List<org.springframework.ai.chat.messages.Message> conversationHistory = new ArrayList<>();
        conversationHistory.addAll(prompt.getInstructions());
        conversationHistory.add(denialAssistantMessage);
        
        
        return ToolExecutionResult.builder()
            .conversationHistory(conversationHistory)
            .returnDirect(true)  
            .build();
    }
    
    
    private void logHighRiskTools(List<ToolCallInfo> highRiskTools) {
        log.warn("========== 고위험 도구 감지 ==========");
        for (ToolCallInfo tool : highRiskTools) {
            SoarTool.RiskLevel risk = policyManager.getRiskLevel(tool.name);
            log.warn("  {} (위험도: {})", tool.name, risk);
        }
        log.warn("=====================================");
    }
    
    
    private void recordExecutionMetrics(
            String requestId,
            List<ToolCallInfo> toolCalls,
            long startTime,
            boolean success) {
        
        long duration = System.currentTimeMillis() - startTime;
        
        
        for (ToolCallInfo tool : toolCalls) {
            executionMetrics.recordExecution(
                tool.name,
                duration,
                success
            );

            
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("tool", tool.name);
            metadata.put("duration", duration * 1_000_000); 
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
    
    
    public int getPendingApprovalsCount() {
        return pendingApprovals.size();
    }
    
    
    public void cancelAllPendingApprovals() {
        log.warn("모든 대기 중인 승인 취소: {} 개", pendingApprovals.size());
        pendingApprovals.forEach((id, future) -> future.cancel(true));
        pendingApprovals.clear();
    }
    
    
    public void setCurrentContext(SoarContext context) {
        currentContext.set(context);
    }
    
    
    public void clearCurrentContext() {
        currentContext.remove();
    }
    
    
    private SoarExecutionMode getExecutionMode() {
        SoarContext context = currentContext.get();
        if (context != null && context.getExecutionMode() != null) {
            SoarExecutionMode mode = context.getExecutionMode();
            
            
            if (mode == SoarExecutionMode.AUTO) {
                
                
                return SoarExecutionMode.ASYNC;
            }
            
            return mode;
        }
        
        
        return SoarExecutionMode.SYNC;
    }
    
    
    private ToolExecutionResult handleAsyncApproval(
            String requestId,
            List<ToolCallInfo> highRiskTools,
            List<ToolCallInfo> allToolCalls,
            Prompt prompt,
            ChatResponse chatResponse) {
        
        try {
            log.info("비동기 모드: 도구 실행 컨텍스트를 DB에 저장 (요청 ID: {})", requestId);
            
            
            ApprovalRequest approvalRequest = buildApprovalRequest(requestId, highRiskTools);
            
            
            ToolExecutionContext executionContext = saveToolExecutionContext(
                requestId,
                highRiskTools.get(0), 
                prompt,
                chatResponse
            );
            
            
            notificationService.sendAsyncApprovalRequest(approvalRequest, executionContext);
            
            
            approvalService.registerAsyncApproval(approvalRequest, executionContext);
            
            
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
                .returnDirect(false) 
                .build();
            
        } catch (Exception e) {
            log.error("비동기 승인 처리 중 오류 (요청 ID: {})", requestId, e);
            
            return requestAndWaitForApprovalSync(requestId, highRiskTools, prompt, chatResponse);
        }
    }
    
    
    private ToolExecutionContext saveToolExecutionContext(
            String requestId,
            ToolCallInfo toolCall,
            Prompt prompt,
            ChatResponse chatResponse) throws Exception {
        
        SoarContext soarContext = currentContext.get();
        
        
        List<Map<String, String>> promptData = new ArrayList<>();
        for (org.springframework.ai.chat.messages.Message msg : prompt.getInstructions()) {
            Map<String, String> msgData = new HashMap<>();
            msgData.put("role", msg.getMessageType().name().toLowerCase());
            msgData.put("content", msg.getText());
            promptData.add(msgData);
        }
        String promptJson = objectMapper.writeValueAsString(promptData);
        
        
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
        
        
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("toolCallId", toolCall.id);
        responseData.put("toolName", toolCall.name);
        responseData.put("arguments", toolCall.arguments);
        String responseJson = objectMapper.writeValueAsString(responseData);
        
        
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
            .expiresAt(LocalDateTime.now().plusMinutes(30)) 
            .build();
        
        return contextRepository.save(context);
    }
    
    
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
        
        
        return delegate.executeToolCalls(prompt, chatResponse);
    }
}