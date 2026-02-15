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

            SoarExecutionMode executionMode = getExecutionMode();

            List<ToolCallInfo> toolCalls = extractToolCalls(chatResponse);

            if (toolCalls.isEmpty()) {
                return delegate.executeToolCalls(prompt, chatResponse);
            }

            List<ToolCallInfo> highRiskTools = identifyHighRiskTools(toolCalls, prompt.getOptions());

            if (!highRiskTools.isEmpty()) {
                log.error("High-risk tools detected: {} count", highRiskTools.size());
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

                        log.error("Tool execution denied (request ID: {})", requestId);
                        return createDenialResult(toolCalls, prompt, chatResponse);
                    }

                }
            } else {
            }

            ToolExecutionResult result = delegate.executeToolCalls(prompt, chatResponse);

            recordExecutionMetrics(requestId, toolCalls, startTime, true);

            notifyExecutionComplete(requestId, toolCalls, result);

            return result;

        } catch (Exception e) {
            log.error("Error during tool execution (request ID: {})", requestId, e);
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

            if (message != null) {
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
            }
        }

        return highRiskTools;
    }

    private SoarTool.RiskLevel checkToolRiskFromOptions(
            String toolName,
            ToolCallingChatOptions options,
            SoarTool.RiskLevel currentLevel) {

        List<ToolCallback> callbacks = options.getToolCallbacks();
        if (callbacks.isEmpty()) {
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
                riskLevel == SoarTool.RiskLevel.CRITICAL ||
                riskLevel == SoarTool.RiskLevel.MEDIUM;
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
            log.error("Approval timeout ({}s elapsed)", APPROVAL_TIMEOUT_SECONDS);
            pendingApprovals.remove(requestId);
            return false;
        } catch (Exception e) {
            log.error("Error during approval processing", e);
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
                .reason("Approval required for high-risk tool execution")
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
                "Tool execution denied. Approval is required for high-risk tool execution. " +
                        "Denied tools: %s",
                toolCalls.stream().map(t -> t.name).collect(Collectors.joining(", "))
        );

        AssistantMessage denialAssistantMessage = new AssistantMessage(denialMessage);

        List<org.springframework.ai.chat.messages.Message> conversationHistory = new ArrayList<>(prompt.getInstructions());
        conversationHistory.add(denialAssistantMessage);

        return ToolExecutionResult.builder()
                .conversationHistory(conversationHistory)
                .returnDirect(true)
                .build();
    }

    private void logHighRiskTools(List<ToolCallInfo> highRiskTools) {
        log.error("========== High-risk tools detected ==========");
        for (ToolCallInfo tool : highRiskTools) {
            SoarTool.RiskLevel risk = policyManager.getRiskLevel(tool.name);
            log.error("  {} (risk level: {})", tool.name, risk);
        }
        log.error("===============================================");
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
        log.error("Cancelling all pending approvals: {} count", pendingApprovals.size());
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
                    "Waiting for tool execution approval. (Request ID: %s)\n" +
                            "High-risk tools: %s\n" +
                            "Will be executed automatically after approval.",
                    requestId,
                    highRiskTools.stream().map(t -> t.name).collect(Collectors.joining(", "))
            );

            AssistantMessage pendingAssistantMessage = new AssistantMessage(pendingMessage);

            List<org.springframework.ai.chat.messages.Message> conversationHistory = new ArrayList<>(prompt.getInstructions());
            conversationHistory.add(pendingAssistantMessage);

            return ToolExecutionResult.builder()
                    .conversationHistory(conversationHistory)
                    .returnDirect(false)
                    .build();

        } catch (Exception e) {
            log.error("Error during async approval processing (request ID: {})", requestId, e);

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
            log.error("Tool execution denied (request ID: {})", requestId);
            return createDenialResult(highRiskTools, prompt, chatResponse);
        }

        return delegate.executeToolCalls(prompt, chatResponse);
    }
}