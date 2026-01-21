package io.contexa.contexacoreenterprise.soar.approval;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.ToolResponseMessage;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Slf4j
@RequiredArgsConstructor
public class ConversationHistoryBuilder {

    public List<Message> build(
            List<Message> previousMessages,
            AssistantMessage assistantMessage,
            List<ToolResponseMessage> toolResponses) {
        
        Objects.requireNonNull(previousMessages, "Previous messages cannot be null");
        Objects.requireNonNull(assistantMessage, "Assistant message cannot be null");
        Objects.requireNonNull(toolResponses, "Tool responses cannot be null");

        List<Message> conversationHistory = new ArrayList<>();

        conversationHistory.addAll(previousMessages);

        conversationHistory.add(assistantMessage);

        conversationHistory.addAll(toolResponses);

        return conversationHistory;
    }

    public List<Message> build(
            List<Message> previousMessages,
            AssistantMessage assistantMessage,
            ToolResponseMessage toolResponse) {
        
        return build(previousMessages, assistantMessage, List.of(toolResponse));
    }

    public List<Message> buildWithMcpContext(
            List<Message> previousMessages,
            AssistantMessage assistantMessage,
            List<ToolResponseMessage> toolResponses,
            java.util.Map<String, Object> mcpMetadata) {

        List<Message> conversationHistory = build(previousMessages, assistantMessage, toolResponses);

        if (mcpMetadata != null && !mcpMetadata.isEmpty()) {
                    }
        
        return conversationHistory;
    }

    public List<Message> buildEmpty(List<Message> previousMessages) {
                return new ArrayList<>(previousMessages);
    }

    public boolean isValid(List<Message> conversationHistory) {
        if (conversationHistory == null || conversationHistory.isEmpty()) {
            return false;
        }
        
        boolean hasAssistantMessage = conversationHistory.stream()
            .anyMatch(m -> m instanceof AssistantMessage);
        
        boolean hasToolResponse = conversationHistory.stream()
            .anyMatch(m -> m instanceof ToolResponseMessage);

        if (hasToolResponse && !hasAssistantMessage) {
            log.warn("잘못된 conversation history: ToolResponseMessage는 있지만 AssistantMessage가 없음");
            return false;
        }
        
        return true;
    }

    public java.util.Map<String, Object> getStatistics(List<Message> conversationHistory) {
        if (conversationHistory == null) {
            return java.util.Map.of("error", "null conversation history");
        }
        
        long assistantCount = conversationHistory.stream()
            .filter(m -> m instanceof AssistantMessage)
            .count();
        
        long toolResponseCount = conversationHistory.stream()
            .filter(m -> m instanceof ToolResponseMessage)
            .count();
        
        return java.util.Map.of(
            "totalMessages", conversationHistory.size(),
            "assistantMessages", assistantCount,
            "toolResponseMessages", toolResponseCount,
            "otherMessages", conversationHistory.size() - assistantCount - toolResponseCount,
            "isValid", isValid(conversationHistory)
        );
    }
}