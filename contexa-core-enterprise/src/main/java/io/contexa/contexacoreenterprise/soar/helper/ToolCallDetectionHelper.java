package io.contexa.contexacoreenterprise.soar.helper;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class ToolCallDetectionHelper {

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

    public boolean hasToolCalls(ChatResponse chatResponse) {
        if (chatResponse == null) {
            return false;
        }

        if (chatResponse.hasToolCalls()) {
                        return true;
        }

        if (hasToolCallsInGenerations(chatResponse)) {
                        return true;
        }

        if (hasToolCallsInText(chatResponse)) {
                        return true;
        }
        
        return false;
    }

    private boolean hasToolCallsInGenerations(ChatResponse chatResponse) {
        List<Generation> generations = chatResponse.getResults();
        if (generations == null || generations.isEmpty()) {
            return false;
        }
        
        for (Generation generation : generations) {
            if (generation.getOutput() != null) {
                List<AssistantMessage.ToolCall> toolCalls = generation.getOutput().getToolCalls();
                if (toolCalls != null && !toolCalls.isEmpty()) {
                                        return true;
                }
            }
        }
        
        return false;
    }

    private boolean hasToolCallsInText(ChatResponse chatResponse) {
        String content = extractTextContent(chatResponse);
        if (content == null || content.isEmpty()) {
            return false;
        }

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

    public List<ToolCallInfo> extractToolCalls(ChatResponse chatResponse) {
        List<ToolCallInfo> toolCallInfos = new ArrayList<>();
        
        if (chatResponse == null) {
            return toolCallInfos;
        }

        toolCallInfos.addAll(extractStandardToolCalls(chatResponse));

        if (toolCallInfos.isEmpty()) {
            toolCallInfos.addAll(extractGenerationToolCalls(chatResponse));
        }

        if (toolCallInfos.isEmpty()) {
            toolCallInfos.addAll(extractTextToolCalls(chatResponse));
        }
        
                return toolCallInfos;
    }

    private List<ToolCallInfo> extractStandardToolCalls(ChatResponse chatResponse) {
        List<ToolCallInfo> toolCallInfos = new ArrayList<>();
        
        if (chatResponse.hasToolCalls()) {

                    }
        
        return toolCallInfos;
    }

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
                                            }
                }
            }
        }
        
        return toolCallInfos;
    }

    private List<ToolCallInfo> extractTextToolCalls(ChatResponse chatResponse) {
        List<ToolCallInfo> toolCallInfos = new ArrayList<>();
        
        String content = extractTextContent(chatResponse);
        if (content == null || content.isEmpty()) {
            return toolCallInfos;
        }

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
                    }

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
                            }
        }
        
        return toolCallInfos;
    }

    private String extractTextContent(ChatResponse chatResponse) {
        if (chatResponse.getResult() != null && 
            chatResponse.getResult().getOutput() != null) {
            return chatResponse.getResult().getOutput().getText();
        }

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

    private String extractArguments(String content, int startIndex) {
        
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

    public void logDetectionResult(ChatResponse chatResponse, boolean hasToolCalls) {
        if (hasToolCalls) {
            List<ToolCallInfo> toolCalls = extractToolCalls(chatResponse);
                        for (ToolCallInfo toolCall : toolCalls) {
                            }
        } else {
                    }
    }
}