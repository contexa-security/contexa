package io.contexa.contexacore.std.llm.factory;

import io.contexa.contexacore.std.llm.core.ExecutionContext;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;

/**
 * ChatClient 팩토리 인터페이스
 * 
 * Factory 패턴 적용:
 * - SRP: ChatClient 생성 로직만 담당
 * - OCP: 새로운 생성 전략을 추가할 수 있음
 * - DIP: 구체적인 ChatClient 생성에 의존하지 않음
 */
public interface ChatClientFactory {
    
    /**
     * ChatModel과 ExecutionContext 로부터 ChatClient 생성
     * 
     * @param chatModel 선택된 ChatModel
     * @param context 실행 컨텍스트 (옵션, Advisor 등 포함)
     * @return 구성된 ChatClient
     */
    ChatClient createChatClient(ChatModel chatModel, ExecutionContext context);
    
    /**
     * 기본 ChatClient 생성 (최소 구성)
     * 
     * @param chatModel 선택된 ChatModel
     * @return 기본 ChatClient
     */
    ChatClient createDefaultChatClient(ChatModel chatModel);
    
    /**
     * 캐시된 ChatClient 조회 (성능 최적화)
     * 
     * @param cacheKey 캐시 키
     * @return 캐시된 ChatClient (없으면 null)
     */
    ChatClient getCachedChatClient(String cacheKey);
    
    /**
     * ChatClient 캐시 저장
     * 
     * @param cacheKey 캐시 키
     * @param chatClient 캐시할 ChatClient
     */
    void cacheChatClient(String cacheKey, ChatClient chatClient);
    
    /**
     * 캐시 정리
     */
    void clearCache();
}