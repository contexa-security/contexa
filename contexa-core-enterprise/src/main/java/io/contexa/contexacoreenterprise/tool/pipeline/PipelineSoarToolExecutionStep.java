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
                    log.warn("SOAR 도구 실행 오류. 일반 LLM으로 폴백: {}", error.getMessage());
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
                .doOnError(error -> log.error("[SOAR-TOOL-STEP] 스트리밍 도구 실행 실패", error));
    }

    private Mono<String> executeWithTools(Prompt prompt, PipelineExecutionContext context) {
        ToolCallback[] unifiedTools = chainedToolResolver.getAllToolCallbacks();
        List<String> toolNames = Arrays.stream(unifiedTools).map(tool -> tool.getToolDefinition().name()).toList();
        HashSet<String> uniqueToolNames = new HashSet<>(toolNames);

        if (unifiedTools.length == 0) {
            log.warn("사용 가능한 도구가 없음. 일반 LLM 실행으로 전환");
            return toolCapableLLMClient.call(prompt);
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
                    log.error("도구 실행 중 오류 발생: {}", e.getMessage());
                    toolExecutionFailed = true;
                }

                if (toolExecutionFailed) {
                    log.warn("도구 실행 실패로 인한 처리 중단");
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
                    currentResponse = toolCapableLLMClient.callToolCallbacksResponse(continuePrompt, unifiedTools).block();
                } catch (Exception e) {
                    log.error("LLM 재호출 실패", e);
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
                        log.error("도구 파라미터 검증 실패: {}", e.getMessage());
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
            log.warn("최종 응답 생성 실패 - 기본 JSON 응답 생성");
        }
        context.addStepResult(PipelineConfiguration.PipelineStep.SOAR_TOOL_EXECUTION, finalResponse);
        return finalResponse;
    }

    private String generateDefaultJsonResponse(PipelineExecutionContext context) {
        SoarResponse response = new SoarResponse();

        response.setAnalysisResult("도구 실행은 완료되었으나 AI가 최종 분석을 생성하지 못했습니다.");
        response.setSummary("도구 실행 결과를 수동으로 검토해 주세요.");
        response.setRecommendations(Arrays.asList(
                "도구 실행 로그 확인",
                "수동 분석 필요",
                "재시도 권장"
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

        return String.format("""
                        {
                            "analysisResult": "%s",
                            "summary": "%s",
                            "recommendations": %s,
                            "sessionState": "%s",
                            "executedTools": %s,
                            "threatLevel": "%s",
                            "incidentId": "%s",
                            "sessionId": "%s"
                        }
                        """,
                response.getAnalysisResult() != null ? response.getAnalysisResult() : "",
                response.getSummary() != null ? response.getSummary() : "",
                formatList(response.getRecommendations()),
                response.getSessionState() != null ? response.getSessionState().toString() : "UNKNOWN",
                formatList(response.getExecutedTools()),
                response.getThreatLevel() != null ? response.getThreatLevel().toString() : "UNKNOWN",
                response.getIncidentId() != null ? response.getIncidentId() : "",
                response.getSessionId() != null ? response.getSessionId() : ""
        );
    }

    private String formatList(List<String> list) {
        if (list == null || list.isEmpty()) {
            return "[]";
        }
        return "[" + list.stream()
                .map(item -> "\"" + item + "\"")
                .reduce((a, b) -> a + ", " + b)
                .orElse("") + "]";
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
    }

    private void logToolExecutionError(String requestId, Throwable error, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
        log.error("[SOAR-TOOL-STEP] ===== 도구 실행 실패 ===== Request: {}, 총 시간: {}ms, 오류: {}",
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

    private String generateToolExecutionSummary(List<String> executedTools) {
        if (executedTools == null || executedTools.isEmpty()) {
            return "도구가 실행되지 않았습니다.";
        }

        StringBuilder summary = new StringBuilder();
        summary.append("도구 실행 요약:\n");
        for (String tool : executedTools) {
            summary.append("- ").append(tool).append(": ");
            summary.append(getToolDescription(tool)).append("\n");
        }
        return summary.toString();
    }

    private String getToolDescription(String toolName) {
        return switch (toolName) {
            case "ip_blocking" -> "악성 IP 차단 완료";
            case "network_isolation" -> "네트워크 격리 수행";
            case "process_kill" -> "악성 프로세스 종료";
            case "session_termination" -> "세션 종료 완료";
            case "file_quarantine" -> "파일 격리 수행";
            case "threat_intelligence" -> "위협 정보 조회 완료";
            case "log_analysis" -> "로그 분석 완료";
            case "network_scan" -> "네트워크 스캔 수행";
            case "audit_logs", "queryAuditLogs" -> "감사 로그 조회 완료";
            default -> "작업 완료";
        };
    }

    private void validateToolParameters(String toolName, String arguments) {

        Set<String> prohibitedFields = Set.of(
                "aiModel", "analysisResult", "confidenceScore",
                "suggestedActions", "riskScore", "sessionState",
                "summary", "recommendations", "executedTools",
                "threatLevel", "incidentId", "sessionId", "timestamp"
        );

        if (arguments != null) {
            for (String field : prohibitedFields) {
                if (arguments.contains("\"" + field + "\"") ||
                        arguments.contains(field + ":") ||
                        arguments.contains(field + "=")) {
                    log.error("도구 파라미터 검증 실패: 도구 {}에 SoarResponse 필드 {} 사용 시도", toolName, field);
                    throw new IllegalArgumentException(
                            String.format("도구 %s에 잘못된 파라미터 %s 사용. SoarResponse 필드는 도구 파라미터로 사용할 수 없습니다.", toolName, field)
                    );
                }
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
                log.warn("⏰ 타임아웃 30초 초과");
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

        String metricsJson = String.format(
                "Tool Execution Metrics: iterations=%d, totalExecutions=%d, uniqueTools=%d, duration=%dms",
                metrics.get("iterations"), metrics.get("totalExecutions"),
                metrics.get("uniqueTools"), metrics.get("duration")
        );

        long duration = (long) metrics.get("duration");
        if (duration > 60000) {
            log.warn("도구 실행 시간 초과: {}ms", duration);
        }

        int totalExecutions = (int) metrics.get("totalExecutions");
        if (totalExecutions > 10) {
            log.warn("과도한 도구 호출: {} 회", totalExecutions);
        }

    }

}