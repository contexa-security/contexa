package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.context.RiskAssessmentContext;
import io.contexa.contexacommon.domain.request.AIRequest;

import java.time.LocalTime;

/**
 * Streaming template for security risk assessment.
 * <p>
 * This template generates prompts for evaluating security risks of
 * access requests with real-time streaming feedback and structured JSON output.
 * </p>
 */
public class RiskAssessmentStreamingTemplate extends AbstractStreamingPromptTemplate {

    @Override
    protected String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return """
            You are not a conversational AI, but a security risk assessment API that outputs data only in the specified JSON format.

            Your risk assessment capabilities include:
            - Time-based analysis (business hours vs. off-hours access)
            - IP-based analysis (internal network vs. external access)
            - Permission-based analysis (authorization verification)
            - Behavior-based analysis (comparison with historical access patterns)
            - Trust score calculation (0.0 to 1.0)
            - Risk level classification (LOW, MEDIUM, HIGH, CRITICAL)
            - Mitigation action recommendations
            """;
    }

    @Override
    protected String getJsonSchemaExample() {
        return """
            {
              "trustScore": 0.85,
              "riskLevel": "LOW",
              "riskTags": ["internal_ip", "business_hours"],
              "summary": "Low risk due to internal IP and access within business hours.",
              "reasoning": "Request from allowed network and within normal business hours.",
              "recommendation": "ALLOW",
              "analysisDetails": {
                "timeAnalysis": "Access within normal business hours.",
                "ipAnalysis": "Access from allowed internal IP range.",
                "permissionAnalysis": "Has appropriate permissions for the requested resource.",
                "behaviorAnalysis": "Normal pattern consistent with past access history."
              },
              "mitigationActions": [],
              "executionTimeMs": 120,
              "completedAt": "2023-10-27T10:00:00Z",
              "status": "COMPLETED"
            }
            """;
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("RiskAssessmentStreaming");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        if (request.getContext() instanceof RiskAssessmentContext context) {
            return buildUserPrompt(context, contextInfo);
        }
        return buildUserPrompt(null, contextInfo);
    }

    /**
     * Builds the user prompt with risk assessment details and execution instructions.
     *
     * @param context the risk assessment context (may be null)
     * @param contextInfo additional context information
     * @return the formatted user prompt
     */
    private String buildUserPrompt(RiskAssessmentContext context, String contextInfo) {
        String requestDetails = (context != null) ?
                String.format("""
                - User ID: %s
                - Time Zone: %s
                - IP Address: %s
                - Requested Resource: %s
                - User Permissions: %s
                """,
                        context.getUserId(),
                        LocalTime.now(),
                        context.getRemoteIp(),
                        context.getResourceIdentifier(),
                        context.getUserPermissions())
                : "Please evaluate security risk based on the provided context information.";

        return String.format("""
            **Risk Assessment Request:**
            %s

            **Reference Context:**
            %s
            %s
            """, requestDetails, contextInfo, buildUserPromptExecutionInstructions());
    }
}
