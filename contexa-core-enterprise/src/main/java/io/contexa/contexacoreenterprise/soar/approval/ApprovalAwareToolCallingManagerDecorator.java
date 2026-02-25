package io.contexa.contexacoreenterprise.soar.approval;

import io.contexa.contexacoreenterprise.soar.config.ToolApprovalPolicyManager;
import io.contexa.contexacoreenterprise.properties.SoarProperties;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarExecutionMode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacoreenterprise.repository.ToolExecutionContextRepository;
import io.contexa.contexacoreenterprise.dashboard.metrics.soar.ToolExecutionMetrics;
import io.contexa.contexacoreenterprise.domain.entity.ToolExecutionContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.DefaultToolCallingManager;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.model.tool.ToolCallingManager;
import org.springframework.ai.model.tool.ToolExecutionResult;
import org.springframework.ai.tool.definition.ToolDefinition;

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
    private final ObjectMapper objectMapper;
    private final SoarProperties soarProperties;

    private final ThreadLocal<SoarContext> currentContext = new ThreadLocal<>();

    private final Map<String, CompletableFuture<Boolean>> pendingApprovals = new ConcurrentHashMap<>();

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

            List<ToolCallInfo> highRiskTools = identifyHighRiskTools(toolCalls);

            if (!highRiskTools.isEmpty()) {

                if (executionMode == SoarExecutionMode.ASYNC) {

                    return handleAsyncApproval(requestId, highRiskTools, toolCalls, prompt, chatResponse);
                } else {

                    boolean approved = requestAndWaitForApproval(
                            requestId,
                            highRiskTools
                    );

                    if (!approved) {

                        log.error("Tool execution denied (request ID: {})", requestId);
                        return createDenialResult(toolCalls, prompt, chatResponse);
                    }

                }
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

        return toolCalls;
    }

    private List<ToolCallInfo> identifyHighRiskTools(List<ToolCallInfo> toolCalls) {
        List<ToolCallInfo> highRiskTools = new ArrayList<>();

        for (ToolCallInfo toolCall : toolCalls) {
            if (policyManager.requiresApproval(toolCall.name)) {
                highRiskTools.add(toolCall);
            }
        }

        return highRiskTools;
    }

    private boolean requestAndWaitForApproval(
            String requestId,
            List<ToolCallInfo> highRiskTools) {

        try {

            ApprovalRequest approvalRequest = buildApprovalRequest(requestId, highRiskTools);

            // Notification handled by McpApprovalNotificationService @EventListener
            CompletableFuture<Boolean> approvalFuture = approvalService.requestApproval(approvalRequest);

            pendingApprovals.put(requestId, approvalFuture);

            long approvalTimeout = soarProperties.getApproval().getTimeout();
            boolean approved = approvalFuture.get(approvalTimeout, TimeUnit.SECONDS);

            pendingApprovals.remove(requestId);

            return approved;

        } catch (TimeoutException e) {
            log.error("Approval timeout ({}s elapsed)", soarProperties.getApproval().getTimeout());
            pendingApprovals.remove(requestId);
            return false;
        } catch (Exception e) {
            log.error("Error during approval processing", e);
            pendingApprovals.remove(requestId);
            return false;
        }
    }

    private ApprovalRequest buildApprovalRequest(String requestId, List<ToolCallInfo> tools) {
        SoarContext soarContext = currentContext.get();

        Map<String, Object> contextMap = new HashMap<>();
        contextMap.put("toolCount", tools.size());
        contextMap.put("toolDetails", tools);
        contextMap.put("timestamp", System.currentTimeMillis());

        if (soarContext != null) {
            contextMap.put("incidentId", soarContext.getIncidentId());
            contextMap.put("sessionId", soarContext.getSessionId());
            contextMap.put("organizationId", soarContext.getOrganizationId());
            contextMap.put("threatType", soarContext.getThreatType());
            contextMap.put("severity", soarContext.getSeverity());
        }

        Map<String, Object> parameters = new HashMap<>();
        for (ToolCallInfo tool : tools) {
            parameters.put(tool.name, tool.arguments);
        }

        return ApprovalRequest.builder()
                .requestId(requestId)
                .requestedAt(LocalDateTime.now())
                .requestedBy("AI System")
                .toolName(tools.stream().map(t -> t.name).collect(Collectors.joining(", ")))
                .reason("Approval required for high-risk tool execution")
                .status(ApprovalRequest.ApprovalStatus.PENDING)
                .context(contextMap)
                .parameters(parameters)
                .build();
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
            metadata.put("duration", duration);
            metadata.put("durationMillis", duration);
            metadata.put("durationNanos", duration * 1_000_000);
            metadata.put("success", success);
            metadata.put("request_id", requestId);

            String eventType = success ? "execution_success" : "execution_failure";
            executionMetrics.recordEvent(eventType, metadata);
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
                    highRiskTools,
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
            List<ToolCallInfo> toolCalls,
            Prompt prompt,
            ChatResponse chatResponse) throws Exception {

        SoarContext soarContext = currentContext.get();
        ToolCallInfo primaryTool = toolCalls.get(0);

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

        List<Map<String, Object>> allToolCallsData = new ArrayList<>();
        for (ToolCallInfo tool : toolCalls) {
            Map<String, Object> toolData = new HashMap<>();
            toolData.put("toolCallId", tool.id);
            toolData.put("toolName", tool.name);
            toolData.put("arguments", tool.arguments);
            allToolCallsData.add(toolData);
        }
        String responseJson = objectMapper.writeValueAsString(allToolCallsData);

        String toolNames = toolCalls.stream().map(t -> t.name).collect(Collectors.joining(", "));

        ToolExecutionContext context = ToolExecutionContext.builder()
                .requestId(requestId)
                .incidentId(soarContext != null ? soarContext.getIncidentId() : null)
                .sessionId(soarContext != null ? soarContext.getSessionId() : null)
                .toolName(toolNames)
                .toolType("SOAR")
                .toolCallId(primaryTool.id)
                .toolArguments(primaryTool.arguments)
                .promptContent(promptJson)
                .chatOptions(chatOptionsJson)
                .chatResponse(responseJson)
                .status("PENDING")
                .expiresAt(LocalDateTime.now().plusMinutes(soarProperties.getToolExecution().getContextExpiryMinutes()))
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
                highRiskTools
        );

        if (!approved) {
            log.error("Tool execution denied (request ID: {})", requestId);
            return createDenialResult(highRiskTools, prompt, chatResponse);
        }

        return delegate.executeToolCalls(prompt, chatResponse);
    }
}
