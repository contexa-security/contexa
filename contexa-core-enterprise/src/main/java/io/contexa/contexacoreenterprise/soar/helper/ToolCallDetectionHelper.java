package io.contexa.contexacoreenterprise.soar.helper;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 도구 호출 감지 헬퍼 클래스
 * 
 * ChatResponse 에서 도구 호출을 감지하고 추출하는 개선된 로직을 제공합니다.
 * Generation 레벨 체크와 텍스트 파싱 폴백을 모두 지원합니다.
 */
@Slf4j
public class ToolCallDetectionHelper {
    
    // 텍스트 파싱을 위한 패턴
    private static final Pattern FUNCTION_CALL_PATTERN = Pattern.compile(
        "function_call|tool_call|execute_tool|run_tool", 
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern JSON_TOOL_PATTERN = Pattern.compile(
        "\\{\\s*\"(tool|function)\"\\s*:\\s*\"([^\"]+)\"",
        Pattern.CASE_INSENSITIVE
    );
    
    private static final Pattern TOOL_NAME_PATTERN = Pattern.compile(
        "\"(name|tool_name|function_name)\"\\s*:\\s*\"([^\"]+)\"",
        Pattern.CASE_INSENSITIVE
    );
    
    /**
     * ChatResponse에서 도구 호출 여부를 감지합니다.
     * 
     * @param chatResponse 검사할 ChatResponse
     * @return 도구 호출이 있으면 true
     */
    public boolean hasToolCalls(ChatResponse chatResponse) {
        if (chatResponse == null) {
            return false;
        }
        
        // 1. 표준 hasToolCalls() 체크
        if (chatResponse.hasToolCalls()) {
            log.debug("표준 hasToolCalls() 감지");
            return true;
        }
        
        // 2. Generation 레벨에서 도구 호출 체크
        if (hasToolCallsInGenerations(chatResponse)) {
            log.debug("Generation 레벨에서 도구 호출 감지");
            return true;
        }
        
        // 3. 텍스트 파싱 폴백
        if (hasToolCallsInText(chatResponse)) {
            log.debug("텍스트 파싱으로 도구 호출 감지 (폴백)");
            return true;
        }
        
        return false;
    }
    
    /**
     * Generation 레벨에서 도구 호출을 확인합니다.
     * 
     * @param chatResponse 검사할 ChatResponse
     * @return 도구 호출이 있으면 true
     */
    private boolean hasToolCallsInGenerations(ChatResponse chatResponse) {
        List<Generation> generations = chatResponse.getResults();
        if (generations == null || generations.isEmpty()) {
            return false;
        }
        
        for (Generation generation : generations) {
            if (generation.getOutput() != null) {
                List<AssistantMessage.ToolCall> toolCalls = generation.getOutput().getToolCalls();
                if (toolCalls != null && !toolCalls.isEmpty()) {
                    log.debug("Generation에서 {} 개의 도구 호출 발견", toolCalls.size());
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * 텍스트 내용을 파싱하여 도구 호출을 감지합니다. (폴백 메커니즘)
     * 
     * @param chatResponse 검사할 ChatResponse
     * @return 도구 호출 패턴이 있으면 true
     */
    private boolean hasToolCallsInText(ChatResponse chatResponse) {
        String content = extractTextContent(chatResponse);
        if (content == null || content.isEmpty()) {
            return false;
        }
        
        // 패턴 매칭
        if (FUNCTION_CALL_PATTERN.matcher(content).find()) {
            return true;
        }
        
        if (JSON_TOOL_PATTERN.matcher(content).find()) {
            return true;
        }
        
        if (TOOL_NAME_PATTERN.matcher(content).find()) {
            return true;
        }
        
        return false;
    }
    
    /**
     * ChatResponse에서 도구 호출 정보를 추출합니다.
     * 
     * @param chatResponse 도구 호출을 추출할 ChatResponse
     * @return 추출된 도구 호출 정보 리스트
     */
    public List<ToolCallInfo> extractToolCalls(ChatResponse chatResponse) {
        List<ToolCallInfo> toolCallInfos = new ArrayList<>();
        
        if (chatResponse == null) {
            return toolCallInfos;
        }
        
        // 1. 표준 방식으로 추출
        toolCallInfos.addAll(extractStandardToolCalls(chatResponse));
        
        // 2. Generation 레벨에서 추출
        if (toolCallInfos.isEmpty()) {
            toolCallInfos.addAll(extractGenerationToolCalls(chatResponse));
        }
        
        // 3. 텍스트 파싱으로 추출 (폴백)
        if (toolCallInfos.isEmpty()) {
            toolCallInfos.addAll(extractTextToolCalls(chatResponse));
        }
        
        log.debug("총 {} 개의 도구 호출 추출됨", toolCallInfos.size());
        return toolCallInfos;
    }
    
    /**
     * 표준 방식으로 도구 호출을 추출합니다.
     */
    private List<ToolCallInfo> extractStandardToolCalls(ChatResponse chatResponse) {
        List<ToolCallInfo> toolCallInfos = new ArrayList<>();
        
        if (chatResponse.hasToolCalls()) {
            // ChatResponse 레벨의 도구 호출 처리
            // 구체적인 구현은 Spring AI 버전에 따라 다를 수 있음
            log.debug("표준 방식으로 도구 호출 추출 시도");
        }
        
        return toolCallInfos;
    }
    
    /**
     * Generation 레벨에서 도구 호출을 추출합니다.
     */
    private List<ToolCallInfo> extractGenerationToolCalls(ChatResponse chatResponse) {
        List<ToolCallInfo> toolCallInfos = new ArrayList<>();
        
        List<Generation> generations = chatResponse.getResults();
        if (generations == null) {
            return toolCallInfos;
        }
        
        for (Generation generation : generations) {
            if (generation.getOutput() != null) {
                List<AssistantMessage.ToolCall> toolCalls = generation.getOutput().getToolCalls();
                if (toolCalls != null) {
                    for (AssistantMessage.ToolCall toolCall : toolCalls) {
                        ToolCallInfo info = new ToolCallInfo(
                            toolCall.id(),
                            toolCall.name(),
                            toolCall.type(),
                            toolCall.arguments()
                        );
                        toolCallInfos.add(info);
                        log.debug("Generation에서 도구 호출 추출: {}", info.getName());
                    }
                }
            }
        }
        
        return toolCallInfos;
    }
    
    /**
     * 텍스트 파싱으로 도구 호출을 추출합니다. (폴백)
     */
    private List<ToolCallInfo> extractTextToolCalls(ChatResponse chatResponse) {
        List<ToolCallInfo> toolCallInfos = new ArrayList<>();
        
        String content = extractTextContent(chatResponse);
        if (content == null || content.isEmpty()) {
            return toolCallInfos;
        }
        
        // JSON 패턴에서 도구 이름 추출
        Matcher jsonMatcher = JSON_TOOL_PATTERN.matcher(content);
        while (jsonMatcher.find()) {
            String toolName = jsonMatcher.group(2);
            ToolCallInfo info = new ToolCallInfo(
                "text-parsed-" + System.currentTimeMillis(),
                toolName,
                "function",
                extractArguments(content, jsonMatcher.end())
            );
            toolCallInfos.add(info);
            log.debug("텍스트 파싱으로 도구 호출 추출: {}", toolName);
        }
        
        // 이름 패턴에서 도구 이름 추출
        if (toolCallInfos.isEmpty()) {
            Matcher nameMatcher = TOOL_NAME_PATTERN.matcher(content);
            while (nameMatcher.find()) {
                String toolName = nameMatcher.group(2);
                ToolCallInfo info = new ToolCallInfo(
                    "text-parsed-" + System.currentTimeMillis(),
                    toolName,
                    "function",
                    extractArguments(content, nameMatcher.end())
                );
                toolCallInfos.add(info);
                log.debug("텍스트 파싱으로 도구 이름 추출: {}", toolName);
            }
        }
        
        return toolCallInfos;
    }
    
    /**
     * ChatResponse에서 텍스트 내용을 추출합니다.
     */
    private String extractTextContent(ChatResponse chatResponse) {
        if (chatResponse.getResult() != null && 
            chatResponse.getResult().getOutput() != null) {
            return chatResponse.getResult().getOutput().getText();
        }
        
        // 모든 Generation의 텍스트 결합
        StringBuilder sb = new StringBuilder();
        List<Generation> generations = chatResponse.getResults();
        if (generations != null) {
            for (Generation generation : generations) {
                if (generation.getOutput() != null && 
                    generation.getOutput().getText() != null) {
                    sb.append(generation.getOutput().getText()).append(" ");
                }
            }
        }
        
        return sb.toString();
    }
    
    /**
     * JSON에서 arguments 부분을 추출합니다.
     */
    private String extractArguments(String content, int startIndex) {
        // 간단한 구현 - 실제로는 더 정교한 JSON 파싱이 필요할 수 있음
        Pattern argsPattern = Pattern.compile(
            "\"(arguments|params|parameters)\"\\s*:\\s*(\\{[^}]*\\}|\\[[^\\]]*\\])",
            Pattern.CASE_INSENSITIVE
        );
        
        Matcher matcher = argsPattern.matcher(content);
        if (matcher.find(startIndex)) {
            return matcher.group(2);
        }
        
        return "{}";
    }
    
    /**
     * 도구 호출 정보를 담는 내부 클래스
     */
    public static class ToolCallInfo {
        private final String id;
        private final String name;
        private final String type;
        private final String arguments;
        
        public ToolCallInfo(String id, String name, String type, String arguments) {
            this.id = id != null ? id : "unknown-" + System.currentTimeMillis();
            this.name = name;
            this.type = type != null ? type : "function";
            this.arguments = arguments != null ? arguments : "{}";
        }
        
        public String getId() { return id; }
        public String getName() { return name; }
        public String getType() { return type; }
        public String getArguments() { return arguments; }
        
        @Override
        public String toString() {
            return String.format("ToolCallInfo{id='%s', name='%s', type='%s'}", 
                id, name, type);
        }
    }
    
    /**
     * 도구 호출 감지 결과를 로깅합니다.
     */
    public void logDetectionResult(ChatResponse chatResponse, boolean hasToolCalls) {
        if (hasToolCalls) {
            List<ToolCallInfo> toolCalls = extractToolCalls(chatResponse);
            log.info("도구 호출 감지 성공: {} 개의 도구", toolCalls.size());
            for (ToolCallInfo toolCall : toolCalls) {
                log.debug("  - {}", toolCall);
            }
        } else {
            log.debug("도구 호출이 감지되지 않음");
        }
    }
}