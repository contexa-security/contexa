package io.contexa.contexacore.std.pipeline.step;

import io.contexa.contexacore.std.components.prompt.PromptGenerator.PromptGenerationResult;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.SessionState;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.std.llm.config.ToolCapableLLMClient;
import io.contexa.contexacore.mcp.tool.resolution.ChainedToolResolver;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacore.soar.approval.ApprovalAwareToolCallingManagerDecorator;
import io.contexa.contexacore.soar.helper.ToolCallDetectionHelper;
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
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.*;

/**
 * SOAR 도구 실행 파이프라인 스텝
 * 
 * LLMExecutionStep을 확장하여 SOAR 도구 실행 기능을 6단계 파이프라인에 통합합니다.
 * AI 진단 프로세스 내에서 도구 호출과 Human-in-the-Loop 승인을 처리합니다.
 */
@Component
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
        log.info("🛠️ [SOAR-TOOL-STEP] ===== SOAR 도구 실행 단계 시작 ===== Request: {}", request.getRequestId());
        
        // SoarContext 인지 확인
        if (!(request.getContext() instanceof SoarContext soarContext)) {
            log.debug("일반 LLM 실행으로 폴백 (SoarContext 아님)");
            return super.execute(request, context);
        }

        // 도구 실행이 필요한지 판단
        if (!isToolExecutionRequired(soarContext)) {
            log.debug("도구 실행 불필요, 일반 LLM 실행");
            return super.execute(request, context);
        }
        
        log.info("도구 실행 필요 감지 - 세션: {}, 인시던트: {}", 
            soarContext.getSessionId(), soarContext.getIncidentId());
        
        // Spring AI 표준 패턴으로 도구 실행
        return preparePrompt(context)
            .flatMap(prompt -> executeWithTools(prompt, context))
            .map(response -> (Object) response)  // String을 Object로 캐스팅
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
        log.info("[SOAR-TOOL-STEP] 스트리밍 SOAR 도구 실행 시작: {}", request.getRequestId());
        
        if (!(request.getContext() instanceof SoarContext)) {
            return super.executeStreaming(request, context);
        }
        
        SoarContext soarContext = (SoarContext) request.getContext();
        
        if (!isToolExecutionRequired(soarContext)) {
            return super.executeStreaming(request, context);
        }
        
        return preparePrompt(context)
            .flatMapMany(prompt -> {
                ToolCallback[] unifiedTools = chainedToolResolver.getAllToolCallbacks();
                log.info("스트리밍 도구 실행: {} 개 도구 준비됨", unifiedTools.length);
                return toolCapableLLMClient.streamToolCallbacks(prompt, unifiedTools);
            })
            .doOnError(error -> log.error("[SOAR-TOOL-STEP] 스트리밍 도구 실행 실패", error));
    }
    
    /**
     * 도구와 함께 LLM 실행 - 2단계 실행 패턴 구현
     * Step 1: 도구 호출 (BeanOutputConverter 없이)
     * Step 2: 응답 생성 (BeanOutputConverter 포함)
     */
    private Mono<String> executeWithTools(Prompt prompt, PipelineExecutionContext context) {
        ToolCallback[] unifiedTools = chainedToolResolver.getAllToolCallbacks();
        List<String> toolNames = Arrays.stream(unifiedTools).map(tool -> tool.getToolDefinition().name()).toList();
        HashSet<String> uniqueToolNames = new HashSet<>(toolNames);

        if (unifiedTools.length == 0) {
            log.warn("사용 가능한 도구가 없음. 일반 LLM 실행으로 전환");
            return toolCapableLLMClient.call(prompt);
        }
        
        log.info("{} 개의 통합 도구 준비 완료 (SOAR + MCP)", unifiedTools.length);
        log.info("등록된 도구 목록: {}", uniqueToolNames);
        
        // 상세 도구 정보 로깅
        log.info("등록된 도구 상세 정보:");
        for (ToolCallback tool : unifiedTools) {
            log.info("  - 도구명: {}", tool.getToolDefinition().name());
            log.info("    설명: {}", tool.getToolDefinition().description());
            // inputTypeSchema() 메서드는 Spring AI 버전에 따라 다를 수 있음
            // log.debug("    파라미터: {}", tool.getToolDefinition().inputTypeSchema());
        }
        
        ChatOptions chatOptions = ToolCallingChatOptions.builder()
                .toolCallbacks(unifiedTools)
                .toolNames(uniqueToolNames)
                .internalToolExecutionEnabled(false)
                .build();
        
        // ChatOptions 설정 확인
        log.debug("ChatOptions 설정: toolCallbacks 개수={}, toolNames={}", 
            unifiedTools.length, uniqueToolNames);
        
        Prompt promptWithOptions = new Prompt(prompt.getInstructions(), chatOptions);
        log.info("Spring AI User-Controlled Tool Execution 활성화");
        
        return toolCapableLLMClient.callToolCallbacksResponse(promptWithOptions, unifiedTools)
            .flatMap(chatResponse -> processToolCallsWithSpringAI(chatResponse, context, promptWithOptions, unifiedTools));
    }
    
    private Mono<String> processToolCallsWithSpringAI(
            ChatResponse initialResponse, 
            PipelineExecutionContext context,
            Prompt originalPrompt,
            ToolCallback[] unifiedTools) {
        
        return Mono.fromCallable(() -> {
            // 도구 호출 컨텍스트 생성
            ToolCallContext toolContext = new ToolCallContext();
            ChatResponse currentResponse = initialResponse;
            
            // Spring AI 표준 패턴: while 루프로 도구 호출 처리
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
                
                log.info("도구 호출 반복 #{}, 실행 도구: {}, 누적 실행: {}", 
                    toolContext.getIterationCount(), 
                    currentToolNames,
                    toolContext.getTotalExecutionCount());

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
                
                log.debug("도구 실행 후 LLM 재호출. Conversation history 크기: {} 메시지, 메트릭: {}", 
                         enhancedHistory.size(),
                         toolContext.getMetrics());
                
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
    
    /**
     * ChatResponse에서 도구 이름 추출
     * JavaSDKMCPClient_ prefix를 제거하고 실제 도구 이름만 반환
     */
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
                    log.debug("도구 이름 추출: {} (원본: {})", name, toolCall.name());

                    // 도구 호출 파라미터 로깅 및 검증
                    String arguments = toolCall.arguments();
                    log.info("도구 호출 파라미터 검사:");
                    log.info("  - 도구: {}", name);
                    log.info("  - Arguments: {}", arguments);

                    // 강화된 파라미터 검증 수행
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
    
    /**
     * 최종 응답 생성 - 3단계 폴백 메커니즘
     * ChatResponse 에서 텍스트를 추출하고 컨텍스트에 저장
     */
    private String generateFinalResponse(ChatResponse response, PipelineExecutionContext context) {
        String finalResponse = null;
        
        // 1차 시도: 정상적인 응답 추출
        if (response != null && response.getResult() != null && 
            response.getResult().getOutput() != null) {
            finalResponse = response.getResult().getOutput().getText();
        }
        
        // 2차 시도: 응답이 비어있으면 Generation 목록에서 추출
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
    
    /**
     * 기본 JSON 응답 생성 (SoarResponse 형식)
     * AI가 응답을 생성하지 못한 경우 사용
     * SoarPromptTemplate과 동일한 BeanOutputConverter 포맷 사용
     */
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
        
        // 컨텍스트에서 실행된 도구 목록 가져오기
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
        
        // BeanOutputConverter가 생성하는 것과 동일한 JSON 구조로 직접 변환
        // Spring AI의 BeanOutputConverter는 Jackson을 사용하므로 같은 구조를 유지
        return convertToJson(response);
    }
    
    /**
     * SoarResponse를 JSON 문자열로 변환
     * BeanOutputConverter의 포맷과 일치하도록 구성
     */
    private String convertToJson(SoarResponse response) {
        // BeanOutputConverter가 기대하는 포맷과 동일한 구조
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
    
    /**
     * 리스트를 JSON 배열 문자열로 변환
     */
    private String formatList(List<String> list) {
        if (list == null || list.isEmpty()) {
            return "[]";
        }
        return "[" + list.stream()
            .map(item -> "\"" + item + "\"")
            .reduce((a, b) -> a + ", " + b)
            .orElse("") + "]";
    }
    
    /**
     * ToolExecutionResult에서 도구 응답 텍스트 추출
     */
    private String extractToolResponseText(List<Message> conversationHistory) {
        if (conversationHistory == null || conversationHistory.isEmpty()) {
            return "";
        }
        
        StringBuilder responseText = new StringBuilder();
        for (Message message : conversationHistory) {
            if (message instanceof ToolResponseMessage toolResponse) {
                // ToolResponseMessage의 내용을 텍스트로 추출
                String content = toolResponse.getText();
                if (content != null && !content.isEmpty()) {
                    responseText.append(content).append("\n");
                }
            }
        }
        
        return responseText.toString().trim();
    }
    
    
    
    /**
     * 도구 실행 필요 여부 판단
     */
    private boolean isToolExecutionRequired(SoarContext context) {
        // 명시적 플래그 확인
        if (context.isRequiresToolExecution()) {
            return true;
        }
        
        // 쿼리 의도 분석
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
        
        // 위협 수준 확인
        if (context.getThreatLevel() != null) {
            return context.getThreatLevel() == SoarContext.ThreatLevel.HIGH ||
                   context.getThreatLevel() == SoarContext.ThreatLevel.CRITICAL;
        }
        
        return false;
    }
    
    /**
     * ChatResponse에 도구 호출이 있는지 확인
     * ToolCallDetectionHelper를 사용하여 개선된 감지 로직 적용
     */
    private boolean hasToolCalls(ChatResponse chatResponse) {
        // Helper 클래스를 사용한 개선된 도구 감지
        boolean hasTools = toolCallDetectionHelper.hasToolCalls(chatResponse);
        
        // 감지 결과 로깅
        toolCallDetectionHelper.logDetectionResult(chatResponse, hasTools);
        
        return hasTools;
    }
    
    private Mono<Prompt> preparePrompt(PipelineExecutionContext context) {
        return Mono.fromCallable(() -> {
            PromptGenerationResult promptResult = context.getStepResult(
                    PipelineConfiguration.PipelineStep.PROMPT_GENERATION, PromptGenerationResult.class);

            if (promptResult == null || promptResult.getPrompt() == null) {
                throw new IllegalStateException("Prompt not found in context");
            }
            
            log.info("[SOAR-TOOL-STEP] 프롬프트 준비 완료");
            return promptResult.getPrompt();
        });
    }
    
    private void logToolExecutionSuccess(String requestId, Object response, long startTime) {
        long totalTime = System.currentTimeMillis() - startTime;
        log.info("[SOAR-TOOL-STEP] ===== 도구 실행 완료 ===== Request: {}, 총 시간: {}ms",
                requestId, totalTime);
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
        return 45; // LLMExecutionStep(4)와 ResponseParsingStep(5) 사이
    }
    
    // 아래 메서드들은 이제 사용하지 않지만 참고용으로 주석 처리
    // AI가 도구 실행 후 첫 번째 응답에서 바로 최종 보고서를 생성하도록 개선됨
    
    // /**
    //  * ChatResponse에 텍스트 응답이 있는지 확인
    //  * @deprecated 도구 실행 후 바로 응답을 받도록 개선됨
    //  */
    // private boolean hasTextResponse(ChatResponse response) {
    //     if (response == null || response.getResult() == null) {
    //         return false;
    //     }
    //     
    //     AssistantMessage output = response.getResult().getOutput();
    //     String content = output.getText();
    //     return content != null && !content.trim().isEmpty();
    // }
    
    // /**
    //  * 최종 보고서 명시적 요청
    //  * @deprecated 도구 실행 후 바로 응답을 받도록 개선됨
    //  */
    // private ChatResponse requestFinalReport(...) {
    //     // 이제 사용하지 않음 - 도구 실행 직후 응답 유도
    // }
    
    /**
     * 도구 실행 요약 생성
     */
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
    
    /**
     * 도구 설명 가져오기
     */
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
    
    /**
     * 인시던트 ID 추출
     */
    private String extractIncidentId(PipelineExecutionContext context) {
        Object request = context.getStepResult(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL, Object.class);
        if (request instanceof SoarContext soarContext && soarContext.getIncidentId() != null) {
            return soarContext.getIncidentId();
        }
        return "INC-" + System.currentTimeMillis();
    }
    
    /**
     * 세션 ID 추출
     */
    private String extractSessionId(PipelineExecutionContext context) {
        Object request = context.getStepResult(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL, Object.class);
        if (request instanceof SoarContext soarContext && soarContext.getSessionId() != null) {
            return soarContext.getSessionId();
        }
        return "SES-" + System.currentTimeMillis();
    }
    
    /**
     * 도구 파라미터 검증 - SoarResponse 필드 차단
     * 도구 호출 시 잘못된 파라미터 사용을 방지하는 핵심 검증 로직
     */
    private void validateToolParameters(String toolName, String arguments) {
        // SoarResponse 필드 검출
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
        
        log.debug("도구 파라미터 검증 통과: {}", toolName);
    }
    
    
    
    /**
     * 도구 이름에 따른 위험도 레벨 결정
     * 
     * @param toolName 도구 이름
     * @return 위험도 레벨
     */
    private ApprovalRequest.RiskLevel determineRiskLevel(String toolName) {
        if (toolName == null) {
            return io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.MEDIUM;
        }
        
        String lowerName = toolName.toLowerCase();
        
        // CRITICAL: 시스템 변경, 차단, 격리 등
        if (lowerName.contains("block") || 
            lowerName.contains("isolate") || 
            lowerName.contains("quarantine") ||
            lowerName.contains("delete") ||
            lowerName.contains("terminate")) {
            return io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.CRITICAL;
        }
        
        // HIGH: 실행, 스캔, 분석 등
        if (lowerName.contains("execute") || 
            lowerName.contains("run") || 
            lowerName.contains("scan") ||
            lowerName.contains("analyze")) {
            return io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.HIGH;
        }
        
        // LOW: 조회, 읽기 등
        if (lowerName.contains("read") || 
            lowerName.contains("get") || 
            lowerName.contains("list") ||
            lowerName.contains("view")) {
            return io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.LOW;
        }
        
        // 기본값 MEDIUM
        return io.contexa.contexacore.domain.ApprovalRequest.RiskLevel.MEDIUM;
    }
    
    /**
     * 단순화된 도구 호출 컨텍스트 - 최소한의 안전장치만 유지
     */
    private static class ToolCallContext {
        private int iterationCount = 0;
        private final long startTime = System.currentTimeMillis();
        private static final int MAX_ITERATIONS = 10;  // Spring AI 기본 반복 횟수
        private static final long TIMEOUT_MS = 30000; // 30초 타임아웃
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
            // 단순한 체크: 반복 횟수와 타임아웃만 확인
            if (iterationCount >= MAX_ITERATIONS) {
                log.debug("최대 반복 {} 도달", MAX_ITERATIONS);
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
            // 도구별 실행 횟수 기록
            for (String tool : toolNames) {
                toolExecutionCount.merge(tool, 1, Integer::sum);
            }
        }
        
        /**
         * 간단한 루프 감지 - 같은 도구가 연속 3회 이상 호출되면 경고
         */
        public LoopDetectionResult detectLoop(List<String> currentToolNames) {
            for (String tool : currentToolNames) {
                Integer count = toolExecutionCount.get(tool);
                if (count != null && count >= 3) {
                    return new LoopDetectionResult(true, 
                        String.format("도구 %s가 %d회 이상 호출됨", tool, count));
                }
            }
            return new LoopDetectionResult(false, "");
        }
        
        
        public int getTotalExecutionCount() {
            return executedTools.size();
        }
        
        public List<String> getAllExecutedTools() {
            return new ArrayList<>(executedTools);
        }
        
        public void logTerminationStatus() {
            log.info("도구 실행 완료 - 반복: {}, 도구 수: {}, 경과 시간: {}ms",
                iterationCount, executedTools.size(), getElapsedTime());
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
    
    /**
     * 단순화된 루프 감지 결과 - Phase 분리로 최소화
     */
    private static class LoopDetectionResult {
        private final boolean loopDetected;
        private final String reason;
        
        public LoopDetectionResult(boolean loopDetected, String reason) {
            this.loopDetected = loopDetected;
            this.reason = reason;
        }
        
        public boolean isLoopDetected() {
            return loopDetected;
        }
        
        public String getReason() {
            return reason;
        }
    }
    
    /**
     * 루프 감지 시 종료 응답 생성 (JSON 형식)
     */
    private String generateTerminationResponse(ChatResponse lastResponse, 
                                              PipelineExecutionContext context,
                                              String terminationReason) {
        log.warn("도구 호출 루프 감지로 인한 종료: {}", terminationReason);
        
        // 실행된 도구 목록 가져오기
        @SuppressWarnings("unchecked")
        List<String> executedTools = context.getMetadata("executedTools", List.class);
        if (executedTools == null) {
            executedTools = new ArrayList<>();
        }
        
        // 도구 목록을 JSON 배열 문자열로 변환
        String toolsJson = executedTools.stream()
            .map(tool -> "\"" + tool + "\"")
            .collect(java.util.stream.Collectors.joining(", "));
        
        // 유효한 SoarResponse JSON 생성
        String jsonResponse = String.format("""
            {
                "analysisResult": "도구 실행이 완료되었습니다. %s",
                "summary": "%s로 인한 분석 종료. 총 %d개의 도구가 실행되었습니다.",
                "recommendations": [
                    "수집된 데이터를 기반으로 보안 대응을 수행하세요",
                    "추가 분석이 필요한 경우 다른 도구를 사용하세요",
                    "반복된 도구 호출은 자동으로 중단되었습니다"
                ],
                "sessionState": "COMPLETED",
                "executedTools": [%s],
                "threatLevel": "MEDIUM",
                "incidentId": "%s",
                "timestamp": "%s"
            }
            """, 
            terminationReason.replace("\"", "'"),
            terminationReason.replace("\"", "'"),
            executedTools.size(),
            toolsJson,
            context.getMetadata("incidentId", String.class) != null ? context.getMetadata("incidentId", String.class) : "auto-generated",
            LocalDateTime.now().toString());
        
        context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, jsonResponse);
        return jsonResponse;
    }
    
    /**
     * 도구 호출이 필요한지 판단
     */
    private boolean isToolCallRequired(Prompt originalPrompt) {
        // 사용자 입력 추출
        String userInput = extractUserInput(originalPrompt);
        
        // Level 1: 명시적 도구 언급 확인
        if (containsToolNames(userInput)) {
            log.info("도구 이름이 명시적으로 언급됨 - 도구 호출 필요");
            return true;
        }
        
        // Level 2: 도구 필요 액션 키워드 확인
        if (containsActionKeywords(userInput)) {
            log.info("⚡ 액션 키워드 감지 - 도구 호출 권장");
            return true;
        }
        
        // Level 3: AI 자율 판단
        log.info("도구 호출 필요성을 AI가 자율 판단");
        return false;
    }
    
    /**
     * 사용자가 요청한 도구 추출
     */
    private Set<String> extractRequestedTools(Prompt prompt) {
        Set<String> requestedTools = new HashSet<>();
        String userInput = extractUserInput(prompt);
        
        // 도구 이름 목록
        Set<String> toolNames = Set.of(
            "threat_intelligence", "log_analysis", "ip_blocking",
            "network_isolation", "process_kill", "session_termination",
            "file_quarantine", "network_scan", "audit_logs"
        );
        
        for (String toolName : toolNames) {
            if (userInput.toLowerCase().contains(toolName)) {
                requestedTools.add(toolName);
            }
        }
        
        return requestedTools;
    }
    
    /**
     * 사용자 입력 추출
     */
    private String extractUserInput(Prompt prompt) {
        StringBuilder input = new StringBuilder();
        for (Message msg : prompt.getInstructions()) {
            if (msg instanceof UserMessage) {
                input.append(msg.getText()).append(" ");
            }
        }
        return input.toString();
    }
    
    /**
     * 도구 이름 포함 여부 확인
     */
    private boolean containsToolNames(String input) {
        if (input == null) return false;
        
        String lowerInput = input.toLowerCase();
        Set<String> toolNames = Set.of(
            "threat_intelligence", "log_analysis", "ip_blocking",
            "network_isolation", "process_kill", "session_termination",
            "file_quarantine", "network_scan", "audit_logs", "queryauditlogs"
        );
        
        for (String toolName : toolNames) {
            if (lowerInput.contains(toolName)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 액션 키워드 포함 여부 확인
     */
    private boolean containsActionKeywords(String input) {
        if (input == null) return false;
        
        String lowerInput = input.toLowerCase();
        Set<String> actionKeywords = Set.of(
            "조회", "차단", "격리", "종료", "스캔", "분석", "검사",
            "block", "isolate", "kill", "terminate", "scan", "analyze", "query"
        );
        
        for (String keyword : actionKeywords) {
            if (lowerInput.contains(keyword)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 도구 실행 메트릭 기록
     */
    private void recordToolExecutionMetrics(ToolCallContext toolContext, 
                                           PipelineExecutionContext context) {
        Map<String, Object> metrics = toolContext.getMetrics();
        
        // 메트릭을 JSON 문자열로 변환
        String metricsJson = String.format(
            "Tool Execution Metrics: iterations=%d, totalExecutions=%d, uniqueTools=%d, duration=%dms",
            metrics.get("iterations"), metrics.get("totalExecutions"), 
            metrics.get("uniqueTools"), metrics.get("duration")
        );
        
        // 성능 임계값 체크 및 경고
        long duration = (long) metrics.get("duration");
        if (duration > 60000) { // 1분 초과
            log.warn("도구 실행 시간 초과: {}ms", duration);
        }
        
        int totalExecutions = (int) metrics.get("totalExecutions");
        if (totalExecutions > 10) {
            log.warn("과도한 도구 호출: {} 회", totalExecutions);
        }
        
        log.info("{}", metricsJson);
    }
    
}