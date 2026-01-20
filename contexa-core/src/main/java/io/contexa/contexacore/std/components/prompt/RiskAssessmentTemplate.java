package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.TrustAssessment;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import org.springframework.ai.converter.BeanOutputConverter;
import org.springframework.stereotype.Component;


@PromptTemplateConfig(
        key = "riskAssessment",
        aliases = {"zeroTrustAssessment", "securityRiskAnalysis", "riskAssessment"},
        description = "Spring AI Structured Output Risk Assessment Template"
)
public class RiskAssessmentTemplate implements PromptTemplate {
    
    
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

    
    private String buildSystemPrompt(String systemMetadata) {
        
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

    
    private String buildUserPrompt(RiskAssessmentContext ctx, AIRequest<? extends DomainContext> request, String contextInfo) {
        
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
        
        
        return assessmentRequest + "\n\n" + converter.getFormat();
    }
    
    
    public BeanOutputConverter<TrustAssessment> getConverter() {
        return converter;
    }
    
    
    public String getTemplateKey() {
        return "riskAssessment";
    }
    
    
    @Override
    public Class<?> getAIGenerationType() {
        return TrustAssessment.class;
    }
}