package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.stereotype.Component;

/**
 * 최적화된 실시간 위험 평가 템플릿
 *
 * Spring AI BeanOutputConverter를 활용한 구조화된 출력:
 * - 자동 JSON 스키마 생성
 * - 타입 안전 변환
 * - 표준화된 포맷 지시
 * - 성능 최적화 (5-10초 목표)
 *
 * Spring AI 공식 패턴 준수
 */
@Component
@PromptTemplateConfig(
        key = "riskAssessment",
        aliases = {"zeroTrustAssessment", "securityRiskAnalysis", "riskAssessment"},
        description = "Spring AI Structured Output Risk Assessment Template"
)
public class RiskAssessmentTemplate implements PromptTemplate {
    
    // Spring AI BeanOutputConverter를 사용한 포맷 생성 - TrustAssessment만 생성
    private final BeanOutputConverter<TrustAssessment> converter = new BeanOutputConverter<>(TrustAssessment.class);

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return buildSystemPrompt(systemMetadata);
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        if (request.getContext() instanceof RiskAssessmentContext context) {
            return buildUserPrompt(context, request, contextInfo);
        }
        throw new IllegalArgumentException("Unsupported context type: " + request.getContext().getClass());
    }

    /**
     * ⚡ Spring AI BeanOutputConverter를 활용한 시스템 프롬프트
     */
    private String buildSystemPrompt(String systemMetadata) {
        // Spring AI의 포맷 지시사항 자동 생성
        String formatInstructions = converter.getFormat();
        
        return String.format("""
                You are a real-time security risk assessment AI.
                
                IMPORTANT: Response must be in PURE JSON format.
                Language: 'summary' and 'riskTags' must be in Korean (한국어).
                
                Score Guidelines:
                - 0.8-1.0: SAFE (Low Risk)
                - 0.5-0.7: WARNING (Medium Risk)
                - 0.0-0.4: DANGER (High Risk)
                
                Consider these factors:
                - Access time (business hours vs off-hours)
                - IP location and history
                - User privileges vs requested resources
                - Behavioral patterns and anomalies
                
                %s
                
                Additional Requirements:
                - 'score' field: Must be a double between 0.0 and 1.0
                - 'riskTags' field: Array of risk indicators in Korean
                - 'summary' field: Brief explanation in Korean (max 30 characters)
                
                %s
            """, formatInstructions, systemMetadata != null ? systemMetadata : "");
    }

    /**
     * ⚡ 구조화된 사용자 프롬프트 (Spring AI 표준)
     */
    private String buildUserPrompt(RiskAssessmentContext ctx, AIRequest<? extends DomainContext> request, String contextInfo) {
        // TrustAssessment 객체에 맞는 JSON 형식으로 응답하도록 요청
        String assessmentRequest = String.format("""
                Assess the following access request and provide risk assessment:
                
                Request Details:
                - User ID: %s
                - User Roles: %s
                - Action Type: %s
                - Target Resource: %s
                - Source IP: %s
                - Request Time: %s
                - Additional Context: %s
                
                Generate a TrustAssessment JSON object with:
                1. score: Trust score (0.0-1.0, where 1.0 is most trusted)
                2. riskTags: List of identified risk factors in Korean
                3. summary: Brief Korean explanation (max 30 chars)
                
                Analyze for:
                - Unusual access patterns
                - IP reputation and location
                - Time-based anomalies
                - Privilege escalation attempts
                - Resource sensitivity
            """,
                ctx.getUserId(),
                ctx.getUserRoles() == null ? "unknown" : String.join(", ", ctx.getUserRoles()),
                ctx.getActionType(),
                ctx.getResourceIdentifier(),
                ctx.getRemoteIp(),
                java.time.LocalDateTime.now(),
                contextInfo == null ? "none" : (contextInfo.length() > 200 ? 
                    contextInfo.substring(0, 200) + "..." : contextInfo)
        );
        
        // BeanOutputConverter의 포맷 지시사항을 다시 추가 (강조)
        return assessmentRequest + "\n\n" + converter.getFormat();
    }
    
    /**
     * BeanOutputConverter 반환 (파이프라인에서 사용)
     * TrustAssessment만 반환하도록 변경
     */
    public BeanOutputConverter<TrustAssessment> getConverter() {
        return converter;
    }
    
    /**
     * 템플릿 키 반환 (PostProcessor가 사용)
     */
    public String getTemplateKey() {
        return "riskAssessment";
    }
    
    /**
     * AI가 실제로 생성할 타입 반환
     * RiskAssessmentResponse가 아닌 TrustAssessment를 생성
     */
    @Override
    public Class<?> getAIGenerationType() {
        return TrustAssessment.class;
    }
}