package io.contexa.contexacoreenterprise.tool.pipeline;

import io.contexa.contexacore.std.components.prompt.PromptGenerator.PromptGenerationResult;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.SessionState;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacoreenterprise.mcp.tool.resolution.ChainedToolResolver;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.LLMExecutionStep;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalAwareToolCallingManagerDecorator;
import io.contexa.contexacoreenterprise.soar.helper.ToolCallDetectionHelper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.ToolResponseMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.ToolCallingChatOptions;
import org.springframework.ai.model.tool.ToolExecutionResult;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.beans.factory.annotation.Qualifier;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.*;

@Qualifier("pipelineSoarToolExecutionStep")
@Slf4j
public class PipelineSoarToolExecutionStep extends LLMExecutionStep {

    private final ToolCapableLLMClient toolCapableLLMClient;
    private final ApprovalAwareToolCallingManagerDecorator approvalAwareToolCallingManager;
    private final ToolCallDetectionHelper toolCallDetectionHelper;
    private final ChainedToolResolver chainedToolResolver;

    public PipelineSoarToolExecutionStep(
            ToolCapableLLMClient toolCapableLLMClient,
            ApprovalAwareToolCallingManagerDecorator approvalAwareToolCallingManager,
            ToolCallDetectionHelper toolCallDetectionHelper,
            ChainedToolResolver chainedToolResolver) {
        super(toolCapableLLMClient);
        this.toolCapableLLMClient = toolCapableLLMClient;
        this.approvalAwareToolCallingManager = approvalAwareToolCallingManager;
        this.toolCallDetectionHelper = toolCallDetectionHelper;
        this.chainedToolResolver = chainedToolResolver;
    }

    @Override
    public <T extends DomainContext> Mono<Object> execute(AIRequest<T> request, PipelineExecutionContext context) {
        long stepStartTime = System.currentTimeMillis();

        if (!(request.getContext() instanceof SoarContext soarContext)) {
            return super.execute(request, context);
        }

        if (!isToolExecutionRequired(soarContext)) {
            return super.execute(request, context);
        }

        return preparePrompt(context)
                .flatMap(prompt -> executeWithTools(prompt, context))
                .map(response -> (Object) response)
                .doOnSuccess(response -> {
                    context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, response);
                    logToolExecutionSuccess(request.getRequestId(), response.toString(), stepStartTime);
                })
                .doOnError(error -> logToolExecutionError(request.getRequestId(), error, stepStartTime))
                .onErrorResume(error -> {
                    log.error("SOAR tool execution error, falling back to LLM: {}", error.getMessage());
                    return super.execute(request, context);
                });
    }

    @Override
    public <T extends DomainContext> Flux<String> executeStreaming(AIRequest<T> request, PipelineExecutionContext context) {

        if (!(request.getContext() instanceof SoarContext soarContext)) {
            return super.executeStreaming(request, context);
        }

        if (!isToolExecutionRequired(soarContext)) {
            return super.executeStreaming(request, context);
        }

        return preparePrompt(context)
                .flatMapMany(prompt -> {
                    ToolCallback[] unifiedTools = chainedToolResolver.getAllToolCallbacks();
                    return toolCapableLLMClient.streamToolCallbacks(prompt, unifiedTools);
                })
                .doOnError(error -> log.error("[SOAR-TOOL-STEP] Streaming tool execution failed", error));
    }

    private Mono<String> executeWithTools(Prompt prompt, PipelineExecutionContext context) {
        ToolCallback[] unifiedTools = chainedToolResolver.getAllToolCallbacks();
        List<String> toolNames = Arrays.stream(unifiedTools).map(tool -> tool.getToolDefinition().name()).toList();
        HashSet<String> uniqueToolNames = new HashSet<>(toolNames);

        if (unifiedTools.length == 0) {
            log.error("No SOAR tools available - aborting execution");
            return Mono.error(new IllegalStateException("No SOAR tools registered for execution"));
        }

        ChatOptions chatOptions = ToolCallingChatOptions.builder()
                .toolCallbacks(unifiedTools)
                .toolNames(uniqueToolNames)
                .internalToolExecutionEnabled(false)
                .build();

        Prompt promptWithOptions = new Prompt(prompt.getInstructions(), chatOptions);

        return toolCapableLLMClient.callToolCallbacksResponse(promptWithOptions, unifiedTools)
                .flatMap(chatResponse -> processToolCallsWithSpringAI(chatResponse, context, promptWithOptions, unifiedTools));
    }

    private Mono<String> processToolCallsWithSpringAI(
            ChatResponse initialResponse,
            PipelineExecutionContext context,
            Prompt originalPrompt,
            ToolCallback[] unifiedTools) {

        return Mono.fromCallable(() -> {

            ToolCallContext toolContext = new ToolCallContext();
            ChatResponse currentResponse = initialResponse;

            while (hasToolCalls(currentResponse) && toolContext.shouldContinue()) {
                toolContext.incrementIteration();

                List<String> currentToolNames = extractToolNamesFromResponse(currentResponse);
                toolContext.recordToolExecution(currentToolNames);

                List<String> executedTools = context.getMetadata("executedTools", List.class);
                if (executedTools == null) {
                    executedTools = new ArrayList<>();
                }
                executedTools.addAll(currentToolNames);
                context.addMetadata("executedTools", executedTools);

                ToolExecutionResult toolExecutionResult = null;
                boolean toolExecutionFailed = false;

                try {
                    toolExecutionResult = approvalAwareToolCallingManager.executeToolCalls(originalPrompt, currentResponse);
                } catch (Exception e) {
                    log.error("Error occurred during tool execution: {}", e.getMessage());
                    toolExecutionFailed = true;
                }

                if (toolExecutionFailed) {
                    log.error("Processing aborted due to tool execution failure");
                    break;
                }

                if (toolExecutionResult.returnDirect()) {
                    String directResponse = extractToolResponseText(toolExecutionResult.conversationHistory());
                    context.addStepResult(PipelineConfiguration.PipelineStep.SOAR_TOOL_EXECUTION, directResponse);
                    return directResponse;
                }

                List<Message> enhancedHistory = new ArrayList<>(toolExecutionResult.conversationHistory());
                Prompt continuePrompt = new Prompt(toolExecutionResult.conversationHistory(), originalPrompt.getOptions());

                try {
                    currentResponse = toolCapableLLMClient.callToolCallbacksResponse(continuePrompt, unifiedTools).block(java.time.Duration.ofSeconds(30));
                } catch (Exception e) {
                    log.error("LLM re-invocation failed", e);
                    break;
                }
            }

            context.addMetadata("executedTools", toolContext.getAllExecutedTools());

            String finalResponse = generateFinalResponse(currentResponse, context);
            recordToolExecutionMetrics(toolContext, context);
            return finalResponse;
        });
    }

    private List<String> extractToolNamesFromResponse(ChatResponse response) {
        List<String> toolNames = new ArrayList<>();
        if (response == null || response.getResults() == null) {
            return toolNames;
        }

        for (Generation generation : response.getResults()) {
            AssistantMessage message = generation.getOutput();
            if (message != null && message.getToolCalls() != null) {
                message.getToolCalls().forEach(toolCall -> {
                    String name = toolCall.name();
                    if (name.startsWith("JavaSDKMCPClient_")) {
                        name = name.substring("JavaSDKMCPClient_".length());
                    }
                    toolNames.add(name);

                    String arguments = toolCall.arguments();

                    try {
                        validateToolParameters(name, arguments);
                    } catch (IllegalArgumentException e) {
                        log.error("Tool parameter validation failed: {}", e.getMessage());
                    }

                });
            }
        }

        return toolNames;
    }

    private String generateFinalResponse(ChatResponse response, PipelineExecutionContext context) {
        String finalResponse = null;

        if (response != null && response.getResult() != null &&
                response.getResult().getOutput() != null) {
            finalResponse = response.getResult().getOutput().getText();
        }

        if ((finalResponse == null || finalResponse.isEmpty()) && response != null) {
            for (Generation generation : response.getResults()) {
                if (generation != null && generation.getOutput() != null) {
                    String text = generation.getOutput().getText();
                    if (text != null && !text.isEmpty()) {
                        finalResponse = text;
                        break;
                    }
                }
            }
        }

        if (finalResponse == null || finalResponse.isEmpty()) {
            finalResponse = generateDefaultJsonResponse(context);
            log.error("Final response generation failed - creating default JSON response");
        }
        context.addStepResult(PipelineConfiguration.PipelineStep.SOAR_TOOL_EXECUTION, finalResponse);
        return finalResponse;
    }

    private String generateDefaultJsonResponse(PipelineExecutionContext context) {
        SoarResponse response = new SoarResponse();

        response.setAnalysisResult("Tool execution completed but AI failed to generate final analysis.");
        response.setSummary("Please manually review the tool execution results.");
        response.setRecommendations(Arrays.asList(
                "Check tool execution logs",
                "Manual analysis required",
                "Retry recommended"
        ));
        response.setSessionState(SessionState.COMPLETED);

        Object executedToolsObj = context.getMetadata("executedTools", Object.class);
        List<String> executedTools = executedToolsObj instanceof List ? (List<String>) executedToolsObj : null;
        response.setExecutedTools(executedTools != null ? executedTools : new ArrayList<>());

        Object request = context.getStepResult(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL, Object.class);
        if (request instanceof SoarContext soarContext) {
            response.setIncidentId(soarContext.getIncidentId());
            response.setSessionId(soarContext.getSessionId());
            response.setThreatLevel(soarContext.getThreatLevel());
        }

        response.setTimestamp(LocalDateTime.now());

        return convertToJson(response);
    }

    private String convertToJson(SoarResponse response) {
        try {
            var objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();
            objectMapper.registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());
            var node = objectMapper.createObjectNode();
            node.put("analysisResult", response.getAnalysisResult() != null ? response.getAnalysisResult() : "");
            node.put("summary", response.getSummary() != null ? response.getSummary() : "");
            node.set("recommendations", objectMapper.valueToTree(
                    response.getRecommendations() != null ? response.getRecommendations() : List.of()));
            node.put("sessionState", response.getSessionState() != null ? response.getSessionState().toString() : "UNKNOWN");
            node.set("executedTools", objectMapper.valueToTree(
                    response.getExecutedTools() != null ? response.getExecutedTools() : List.of()));
            node.put("threatLevel", response.getThreatLevel() != null ? response.getThreatLevel().toString() : "UNKNOWN");
            node.put("incidentId", response.getIncidentId() != null ? response.getIncidentId() : "");
            node.put("sessionId", response.getSessionId() != null ? response.getSessionId() : "");
            return objectMapper.writeValueAsString(node);
        } catch (Exception e) {
            log.error("Failed to serialize SoarResponse to JSON", e);
            return "{}";
        }
    }

    private String extractToolResponseText(List<Message> conversationHistory) {
        if (conversationHistory == null || conversationHistory.isEmpty()) {
            return "";
        }

        StringBuilder responseText = new StringBuilder();
        for (Message message : conversationHistory) {
            if (message instanceof ToolResponseMessage toolResponse) {

                String content = toolResponse.getText();
                if (content != null && !content.isEmpty()) {
                    responseText.append(content).append("\n");
                }
            }
        }

        return responseText.toString().trim();
    }

    private boolean isToolExecutionRequired(SoarContext context) {

        if (context.isRequiresToolExecution()) {
            return true;
        }

        String queryIntent = context.getQueryIntent();
        if (queryIntent != null) {
            String lowerIntent = queryIntent.toLowerCase();
            return lowerIntent.contains("scan") ||
                    lowerIntent.contains("block") ||
                    lowerIntent.contains("isolate") ||
                    lowerIntent.contains("analyze") ||
                    lowerIntent.contains("investigate") ||
                    lowerIntent.contains("execute") ||
                    lowerIntent.contains("run");
        }

        if (context.getThreatLevel() != null) {
            return context.getThreatLevel() == SoarContext.ThreatLevel.HIGH ||
                    context.getThreatLevel() == SoarContext.ThreatLevel.CRITICAL;
        }

        return false;
    }

    private boolean hasToolCalls(ChatResponse chatResponse) {

        boolean hasTools = toolCallDetectionHelper.hasToolCalls(chatResponse);

        toolCallDetectionHelper.logDetectionResult(chatResponse, hasTools);

        return hasTools;
    }

    public Mono<Prompt> preparePrompt(PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
            PromptGenerationResult promptResult = context.getStepResult(
                    PipelineConfiguration.PipelineStep.PROMPT_GENERATION, PromptGenerationResult.class);

            if (promptResult == null || promptResult.getPrompt() == null) {
                throw new IllegalStateException("Prompt not found in context");
            }

            return promptResult.getPrompt();
        });
    }

    private void logToolExecutionSuccess(String requestId, Object response, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
        log.error("[SOAR-TOOL-STEP] Tool execution completed. Request: {}, total time: {}ms", requestId, totalTime);
    }

    private void logToolExecutionError(String requestId, Throwable error, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
        log.error("[SOAR-TOOL-STEP] ===== Tool execution failed ===== Request: {}, total time: {}ms, error: {}",
                requestId, totalTime, error.getMessage());
    }

    @Override
    public String getStepName() {
        return "SOAR_TOOL_EXECUTION";
    }

    @Override
    public int getOrder() {
        return 45;
    }

    private void validateToolParameters(String toolName, String arguments) {

        Set<String> prohibitedFields = Set.of(
                "aiModel", "analysisResult", "confidenceScore",
                "suggestedActions", "riskScore", "sessionState",
                "summary", "recommendations", "executedTools",
                "threatLevel", "incidentId", "sessionId", "timestamp"
        );

        if (arguments != null) {
            try {
                var objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();
                var node = objectMapper.readTree(arguments);
                for (String field : prohibitedFields) {
                    if (node.has(field)) {
                        log.error("Tool parameter validation failed: tool {} attempted to use SoarResponse field {}", toolName, field);
                        throw new IllegalArgumentException(
                                String.format("Prohibited SoarResponse field '%s' in tool '%s' parameters", field, toolName)
                        );
                    }
                }
            } catch (IllegalArgumentException e) {
                throw e;
            } catch (Exception e) {
                log.error("Failed to parse tool arguments as JSON for validation: {}", toolName);
            }
        }

    }

    private static class ToolCallContext {
        private int iterationCount = 0;
        private final long startTime = System.currentTimeMillis();
        private static final int MAX_ITERATIONS = 10;
        private static final long TIMEOUT_MS = 30000;
        private final List<String> executedTools = new ArrayList<>();
        private final Map<String, Integer> toolExecutionCount = new HashMap<>();

        public List<String> getExecutedTools() {
            return new ArrayList<>(executedTools);
        }

        public long getElapsedTime() {
            return System.currentTimeMillis() - startTime;
        }

        public int getIterationCount() {
            return iterationCount;
        }

        public boolean shouldContinue() {

            if (iterationCount >= MAX_ITERATIONS) {
                return false;
            }

            if (System.currentTimeMillis() - startTime > TIMEOUT_MS) {
                log.error("Timeout exceeded 30 seconds");
                return false;
            }

            return true;
        }

        public void incrementIteration() {
            iterationCount++;
        }

        public void recordToolExecution(List<String> toolNames) {
            executedTools.addAll(toolNames);

            for (String tool : toolNames) {
                toolExecutionCount.merge(tool, 1, Integer::sum);
            }
        }
        public List<String> getAllExecutedTools() {
            return new ArrayList<>(executedTools);
        }

        public Map<String, Object> getMetrics() {
            Map<String, Object> metrics = new HashMap<>();
            metrics.put("iterations", iterationCount);
            metrics.put("totalExecutions", executedTools.size());
            metrics.put("uniqueTools", toolExecutionCount.size());
            metrics.put("duration", getElapsedTime());
            return metrics;
        }
    }

    private void recordToolExecutionMetrics(ToolCallContext toolContext,
                                            PipelineExecutionContext context) {
        Map<String, Object> metrics = toolContext.getMetrics();

        long duration = (long) metrics.get("duration");
        if (duration > 60000) {
            log.error("Tool execution time exceeded: {}ms", duration);
        }

        int totalExecutions = (int) metrics.get("totalExecutions");
        if (totalExecutions > 10) {
            log.error("Excessive tool calls: {} times", totalExecutions);
        }

    }

}
