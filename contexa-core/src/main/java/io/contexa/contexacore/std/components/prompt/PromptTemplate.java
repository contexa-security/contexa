package io.contexa.contexacore.std.components.prompt;


import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;

/**
 * 프롬프트 템플릿 인터페이스
 */
public interface PromptTemplate {
    String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata);
    String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo);
    
    /**
     * AI가 실제로 생성할 타입을 반환합니다.
     * 
     * 일부 템플릿의 경우, AI가 생성하는 타입과 최종 응답 타입이 다를 수 있습니다.
     * 예: AI는 TrustAssessment를 생성하지만, 최종 응답은 RiskAssessmentResponse
     * 
     * @return AI가 생성할 타입, 또는 null (기본값)
     */
    default Class<?> getAIGenerationType() {
        return null;
    }
}
