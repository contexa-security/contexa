package io.contexa.contexacore.soar.approval;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.ToolResponseMessage;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Conversation History Builder
 * 
 * Spring AI 표준에 따른 conversation history 구성을 담당합니다.
 * DefaultToolCallingManager의 패턴을 참조하여 구현되었습니다.
 * 
 * Single Responsibility Principle:
 * - 오직 conversation history 구성만을 담당
 * - 도구 실행이나 승인 로직과 분리
 * 
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ConversationHistoryBuilder {
    
    /**
     * Spring AI 표준에 따른 conversation history 구성
     * 
     * DefaultToolCallingManager.buildConversationHistoryAfterToolExecution()과 동일한 패턴:
     * 1. 이전 메시지들 (원본 프롬프트)
     * 2. AI의 도구 호출 요청 (AssistantMessage)
     * 3. 도구 실행 결과들 (ToolResponseMessage)
     * 
     * @param previousMessages 이전 대화 메시지들 (원본 프롬프트)
     * @param assistantMessage AI가 생성한 도구 호출 요청 메시지
     * @param toolResponses 도구 실행 결과 메시지들
     * @return 완성된 conversation history
     */
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
        
        // Spring AI 표준 패턴에 따른 메시지 순서
        List<Message> conversationHistory = new ArrayList<>();
        
        // 1. 이전 메시지들 추가 (원본 프롬프트)
        conversationHistory.addAll(previousMessages);
        log.trace("✓ {} 개의 이전 메시지 추가됨", previousMessages.size());
        
        // 2. AI의 도구 호출 요청 추가 (AssistantMessage)
        conversationHistory.add(assistantMessage);
        log.trace("✓ AssistantMessage 추가됨 (도구 호출 요청)");
        
        // 3. 도구 실행 결과들 추가 (ToolResponseMessage)
        conversationHistory.addAll(toolResponses);
        log.trace("✓ {} 개의 도구 응답 메시지 추가됨", toolResponses.size());
        
        log.debug("Conversation history 구성 완료 (총 {} 메시지)",
                 conversationHistory.size());
        
        return conversationHistory;
    }
    
    /**
     * 단일 도구 응답을 위한 편의 메서드
     * 
     * @param previousMessages 이전 대화 메시지들
     * @param assistantMessage AI가 생성한 도구 호출 요청 메시지
     * @param toolResponse 단일 도구 실행 결과 메시지
     * @return 완성된 conversation history
     */
    public List<Message> build(
            List<Message> previousMessages,
            AssistantMessage assistantMessage,
            ToolResponseMessage toolResponse) {
        
        return build(previousMessages, assistantMessage, List.of(toolResponse));
    }
    
    /**
     * MCP 원격 호출을 위한 특별 처리
     * 
     * MCP 도구 실행 시 추가 메타데이터를 포함하여 conversation history를 구성합니다.
     * 
     * @param previousMessages 이전 대화 메시지들
     * @param assistantMessage AI가 생성한 도구 호출 요청 메시지
     * @param toolResponses 도구 실행 결과 메시지들
     * @param mcpMetadata MCP 관련 메타데이터
     * @return 완성된 conversation history
     */
    public List<Message> buildWithMcpContext(
            List<Message> previousMessages,
            AssistantMessage assistantMessage,
            List<ToolResponseMessage> toolResponses,
            java.util.Map<String, Object> mcpMetadata) {
        
        log.debug("MCP 컨텍스트를 포함한 conversation history 구성");
        
        // 기본 history 구성
        List<Message> conversationHistory = build(previousMessages, assistantMessage, toolResponses);
        
        // MCP 메타데이터 로깅 (디버깅용)
        if (mcpMetadata != null && !mcpMetadata.isEmpty()) {
            log.debug("MCP 메타데이터: {}", mcpMetadata);
        }
        
        return conversationHistory;
    }
    
    /**
     * 빈 conversation history 생성 (도구 호출이 없는 경우)
     * 
     * @param previousMessages 이전 대화 메시지들
     * @return 이전 메시지만 포함된 conversation history
     */
    public List<Message> buildEmpty(List<Message> previousMessages) {
        log.debug("📭 빈 conversation history 구성 (도구 호출 없음)");
        return new ArrayList<>(previousMessages);
    }
    
    /**
     * Conversation history 유효성 검증
     * 
     * @param conversationHistory 검증할 conversation history
     * @return 유효한 경우 true
     */
    public boolean isValid(List<Message> conversationHistory) {
        if (conversationHistory == null || conversationHistory.isEmpty()) {
            return false;
        }
        
        boolean hasAssistantMessage = conversationHistory.stream()
            .anyMatch(m -> m instanceof AssistantMessage);
        
        boolean hasToolResponse = conversationHistory.stream()
            .anyMatch(m -> m instanceof ToolResponseMessage);
        
        // 도구 호출이 있다면 AssistantMessage와 ToolResponseMessage가 모두 있어야 함
        if (hasToolResponse && !hasAssistantMessage) {
            log.warn("잘못된 conversation history: ToolResponseMessage는 있지만 AssistantMessage가 없음");
            return false;
        }
        
        return true;
    }
    
    /**
     * Conversation history 통계 정보
     * 
     * @param conversationHistory 분석할 conversation history
     * @return 통계 정보 맵
     */
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