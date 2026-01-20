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
        
        log.debug("🏗️ Conversation history 구성 시작");
        log.debug("  - 이전 메시지 수: {}", previousMessages.size());
        log.debug("  - 도구 응답 수: {}", toolResponses.size());
        
        
        List<Message> conversationHistory = new ArrayList<>();
        
        
        conversationHistory.addAll(previousMessages);
        log.trace("✓ {} 개의 이전 메시지 추가됨", previousMessages.size());
        
        
        conversationHistory.add(assistantMessage);
        log.trace("✓ AssistantMessage 추가됨 (도구 호출 요청)");
        
        
        conversationHistory.addAll(toolResponses);
        log.trace("✓ {} 개의 도구 응답 메시지 추가됨", toolResponses.size());
        
        log.debug("Conversation history 구성 완료 (총 {} 메시지)",
                 conversationHistory.size());
        
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
        
        log.debug("MCP 컨텍스트를 포함한 conversation history 구성");
        
        
        List<Message> conversationHistory = build(previousMessages, assistantMessage, toolResponses);
        
        
        if (mcpMetadata != null && !mcpMetadata.isEmpty()) {
            log.debug("MCP 메타데이터: {}", mcpMetadata);
        }
        
        return conversationHistory;
    }
    
    
    public List<Message> buildEmpty(List<Message> previousMessages) {
        log.debug("📭 빈 conversation history 구성 (도구 호출 없음)");
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