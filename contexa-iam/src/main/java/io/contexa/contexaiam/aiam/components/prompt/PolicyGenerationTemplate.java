package io.contexa.contexaiam.aiam.components.prompt;

import io.contexa.contexacommon.domain.PromptTemplate;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.converter.BeanOutputConverter;

@Slf4j
public class PolicyGenerationTemplate implements PromptTemplate {

    private final BeanOutputConverter<PolicyResponse> converter = 
        new BeanOutputConverter<>(PolicyResponse.class);

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("PolicyGeneration");
    }

    @Override
    public String generateSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        
        String formatInstructions = converter.getFormat();
        
        return String.format("""
            You are an IAM Policy Generation AI specialized in converting natural language requirements into structured access control policies.
            
            IMPORTANT: Response must be in PURE JSON format matching the PolicyResponse schema.
            Language: Policy names and descriptions must be in Korean (한국어).
            
            Policy Generation Guidelines:
            1. Analyze natural language requirements and context
            2. Map requirements to roles, permissions, and conditions
            3. Generate creative and clear policy names
            4. Write detailed descriptions explaining the policy
            5. Apply principle of least privilege
            6. Include risk assessment when appropriate
            
            Policy Components:
            - policyName: Clear, descriptive name in Korean
            - description: Detailed explanation in Korean
            - roleIds: Array of numeric role IDs
            - permissionIds: Array of numeric permission IDs
            - conditions: Map of condition template IDs to string array values
            - aiRiskAssessmentEnabled: Whether AI risk assessment is active
            - requiredTrustScore: Trust score threshold (0.0-1.0)
            - customConditionSpel: SpEL expression for custom conditions
            - effect: ALLOW or DENY
            - policyConfidenceScore: AI confidence in policy generation (0.0-1.0)
            - appliedRules: Array of business rules applied
            - optimized: Whether policy has been optimized
            
            %s
            
            Business Rule Patterns:
            - Time-based access: Working hours, maintenance windows
            - Location-based: IP ranges, geographic restrictions
            - Risk-based: Trust scores, behavioral analysis
            - Separation of duties: Conflicting role restrictions
            - Approval workflows: Multi-factor authorization
            
            SpEL Expression Examples:
            - #user.department == 'IT' && #time.hour >= 9 && #time.hour <= 18
            - #request.ip.startsWith('192.168.') || #user.hasRole('ADMIN')
            - #resource.classification == 'CONFIDENTIAL' && #user.clearanceLevel >= 3
            
            %s
            """, formatInstructions, systemMetadata != null ? systemMetadata : "");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        String naturalLanguageQuery = extractQueryFromRequest(request);

        String policyRequest = String.format("""
            Generate IAM Policy from Natural Language:
            
            Natural Language Requirement:
            "%s"
            
            Context Information:
            %s
            
            Policy Generation Requirements:
            1. Parse the natural language to identify:
               - Who needs access (roles/users)
               - What they need to access (resources/permissions)
               - When access is allowed (time conditions)
               - Where access is allowed (location conditions)
               - Why access is needed (business justification)
            
            2. Map to policy components:
               - Select appropriate role IDs
               - Choose relevant permission IDs
               - Define necessary conditions
               - Set risk assessment requirements
               - Create SpEL expressions if needed
            
            3. Generate PolicyResponse with:
               - Clear Korean policy name and description
               - Appropriate role and permission mappings
               - Well-structured conditions
               - Confidence score indicating generation quality
               - List of applied business rules
               - Optimization status
            
            Important Notes:
            - Conditions must be string arrays: ["value1", "value2"]
            - NOT object arrays: [{"key": "value"}]
            - Policy names and descriptions in Korean
            - Apply principle of least privilege
            - Include risk assessment for sensitive operations
            
            Generate complete PolicyResponse in JSON format.
            """, naturalLanguageQuery, contextInfo);

        return policyRequest + "\n\n" + converter.getFormat();
    }

    private String extractQueryFromRequest(AIRequest<? extends DomainContext> request) {
        
        String naturalLanguageQuery = request.getParameter("naturalLanguageQuery", String.class);
        if (naturalLanguageQuery != null) {
            return naturalLanguageQuery;
        }

        if (request.getContext() != null) {
            return request.getContext().toString();
        }

        return "자연어 요구사항이 제공되지 않았습니다";
    }

    public BeanOutputConverter<PolicyResponse> getConverter() {
        return converter;
    }
} 