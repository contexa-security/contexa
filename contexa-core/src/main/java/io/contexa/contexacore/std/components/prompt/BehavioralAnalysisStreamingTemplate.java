package io.contexa.contexacore.std.components.prompt;

import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.BehavioralAnalysisContext;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;

/**
 * Streaming template for User and Entity Behavior Analytics (UEBA).
 * <p>
 * This template generates prompts for analyzing user behavioral patterns
 * to detect anomalies with real-time streaming feedback and structured JSON output.
 * </p>
 */
public class BehavioralAnalysisStreamingTemplate extends AbstractStreamingPromptTemplate {

    @Override
    protected String generateDomainSystemPrompt(AIRequest<? extends DomainContext> request, String systemMetadata) {
        return """
            You are a UEBA (User and Entity Behavior Analytics) specialist AI that analyzes user behavioral patterns to detect anomalies.
            You are not a conversational AI, but an API that outputs data only in the specified JSON format.

            Your analysis capabilities include:
            - Establishing baseline behavior patterns from historical data
            - Detecting deviations from normal behavioral patterns
            - Calculating behavioral risk scores (0-100)
            - Identifying specific anomaly types (unusual login time, unusual IP, abnormal resource access, etc.)
            - Providing actionable security recommendations
            """;
    }

    @Override
    protected String getJsonSchemaExample() {
        return """
            {
              "analysisId": "ueba-analysis-UUID",
              "userId": "Target user ID for analysis",
              "behavioralRiskScore": 85.5,
              "riskLevel": "HIGH",
              "summary": "High risk assessment due to access from unusual time and IP to sensitive data.",
              "anomalies": [
                { "timestamp": "2025-07-23T03:15:00Z", "description": "Login attempted at 3 AM, outside normal activity hours (09:00-18:00).", "type": "UNUSUAL_LOGIN_TIME", "riskContribution": 40.0 },
                { "timestamp": "2025-07-23T03:16:10Z", "description": "Access from previously unused overseas IP (14.XX.XX.XX).", "type": "UNUSUAL_IP", "riskContribution": 35.0 },
                { "timestamp": "2025-07-23T03:18:25Z", "description": "Attempted access to admin page ('/api/v1/admin/server-config') that was never accessed before.", "type": "ABNORMAL_RESOURCE_ACCESS", "riskContribution": 25.0 }
              ],
              "recommendations": [
                { "action": "Immediately terminate the user's session", "reason": "Very high possibility of account compromise.", "priority": "HIGH" },
                { "action": "Force MFA reset for the account", "reason": "Authentication credentials may have been leaked.", "priority": "HIGH" },
                { "action": "Send urgent alert to security team about this activity", "reason": "Immediate investigation and response required.", "priority": "MEDIUM" }
              ],
              "visualizationData": {
                "events": [
                  { "timestamp": "2025-07-22T10:05:00Z", "type": "LOGIN", "description": "Login (IP: 192.168.1.10)", "isAnomaly": false },
                  { "timestamp": "2025-07-22T11:20:00Z", "type": "RESOURCE_ACCESS", "description": "Document view (/docs/123)", "isAnomaly": false },
                  { "timestamp": "2025-07-23T03:15:00Z", "type": "LOGIN", "description": "Login (IP: 14.XX.XX.XX)", "isAnomaly": true },
                  { "timestamp": "2025-07-23T03:18:25Z", "type": "RESOURCE_ACCESS", "description": "Admin page access (/api/v1/admin/server-config)", "isAnomaly": true }
                ]
              }
            }
            """;
    }

    @Override
    public TemplateType getSupportedType() {
        return new TemplateType("BehavioralAnalysisStreaming");
    }

    @Override
    public String generateUserPrompt(AIRequest<? extends DomainContext> request, String contextInfo) {
        BehavioralAnalysisContext context = (BehavioralAnalysisContext) request.getContext();
        return buildUserPrompt(context);
    }

    /**
     * Builds the user prompt with behavioral analysis details and execution instructions.
     *
     * @param context the behavioral analysis context
     * @return the formatted user prompt
     */
    private String buildUserPrompt(BehavioralAnalysisContext context) {
        return String.format("""
            **Target User for Analysis:** %s

            **Current Activity Information:**
            - Activity: %s
            - Access IP: %s

            **Historical Behavior Pattern Summary (Last 30 days):**
            %s

            **[Analysis Instructions]**
            1.  Establish normal behavior baseline using the 'Historical Behavior Pattern Summary'.
            2.  Analyze how much the 'Current Activity Information' deviates from the baseline to identify anomalies.
            3.  Evaluate the risk level of each anomaly and calculate an overall 'Behavioral Risk Score' between 0 and 100.
            4.  Explain the analysis process step by step in natural language, then output the final result in the JSON format specified in the system prompt.
            %s
            """, context.getUserId(), context.getCurrentActivity(), context.getRemoteIp(),
                context.getHistoricalBehaviorSummary(), buildUserPromptExecutionInstructions());
    }
}
