package io.contexa.contexacoreenterprise.tool.llm;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.tool.ToolCallback;

import java.util.List;

/**
 * LLM 도구 실행 인터페이스
 *
 * SRP: 도구 실행 로직만 담당
 * OCP: 새로운 도구 실행 전략 추가 가능
 */
public interface LlmToolExecutor {
    
    /**
     * 도구 실행과 함께 텍스트 응답 반환
     * 
     * @param promptSpec ChatClient의 프롬프트 스펙
     * @param toolCallbacks 실행할 도구 콜백들
     * @param toolProviders 도구 제공자들
     * @return 도구 실행 결과가 포함된 텍스트 응답
     */
    String executeWithTools(Object promptSpec, 
                           List<ToolCallback> toolCallbacks,
                           List<Object> toolProviders);
    
    /**
     * 도구 실행과 함께 ChatResponse 반환
     * 
     * @param promptSpec ChatClient의 프롬프트 스펙
     * @param toolCallbacks 실행할 도구 콜백들
     * @param toolProviders 도구 제공자들
     * @return 도구 실행 결과가 포함된 ChatResponse
     */
    ChatResponse executeWithToolsResponse(Object promptSpec,
                                        ToolCallback[] toolCallbacks,
                                        List<Object> toolProviders);
    
    /**
     * SOAR 도구 특화 실행 (Human-in-the-Loop 포함)
     * 
     * @param promptSpec ChatClient의 프롬프트 스펙
     * @param soarToolCallbacks SOAR 도구 콜백들
     * @param incidentId 인시던트 ID
     * @param organizationId 조직 ID
     * @return SOAR 도구 실행 결과
     */
    String executeSoarTools(Object promptSpec,
                           List<ToolCallback> soarToolCallbacks,
                           String incidentId,
                           String organizationId);
    
    /**
     * 도구 실행 가능 여부 확인
     * 
     * @param toolCallbacks 확인할 도구 콜백들
     * @return 실행 가능 여부
     */
    boolean canExecuteTools(List<ToolCallback> toolCallbacks);
}