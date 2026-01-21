package io.contexa.contexamcp.prompts;

import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
public class SecurityAnalysisPrompts {

    public McpSchema.Prompt getLogAnalysisPrompt() {
        return new McpSchema.Prompt(
            "analyze_security_logs",
            "Analyze security logs to identify threats and anomalies",
            List.of(
                new McpSchema.PromptArgument(
                    "log_type",
                    "Type of logs to analyze (firewall, ids, application, system)",
                    true
                ),
                new McpSchema.PromptArgument(
                    "time_range",
                    "Time range for analysis (e.g., last_hour, last_24h, last_week)",
                    false
                ),
                new McpSchema.PromptArgument(
                    "severity_filter",
                    "Filter by severity (critical, high, medium, low)",
                    false
                ),
                new McpSchema.PromptArgument(
                    "focus_area",
                    "Specific area to focus on (authentication, network, file_access)",
                    false
                )
            )
        );
    }

    public McpServerFeatures.SyncPromptSpecification createLogAnalysisSpec() {
        return new McpServerFeatures.SyncPromptSpecification(
            getLogAnalysisPrompt(),
            (exchange, request) -> {
                try {

                    Map<String, Object> args = request.arguments();
                    String logType = (String) args.getOrDefault("log_type", "all");
                    String timeRange = (String) args.getOrDefault("time_range", "last_24h");
                    String severityFilter = (String) args.getOrDefault("severity_filter", "all");
                    String focusArea = (String) args.getOrDefault("focus_area", "general");

                    List<McpSchema.PromptMessage> messages = new ArrayList<>();

                    messages.add(new McpSchema.PromptMessage(
                            McpSchema.Role.USER,
                        new McpSchema.TextContent(buildSystemPrompt())
                    ));

                    messages.add(new McpSchema.PromptMessage(
                            McpSchema.Role.USER,
                        new McpSchema.TextContent(buildUserPrompt(logType, timeRange, severityFilter, focusArea))
                    ));

                    messages.add(new McpSchema.PromptMessage(
                            McpSchema.Role.ASSISTANT,
                        new McpSchema.TextContent(buildAssistantHint(logType))
                    ));
                    
                    return new McpSchema.GetPromptResult(
                        "Security log analysis prompt for " + logType,
                        messages
                    );
                    
                } catch (Exception e) {
                    log.error("Failed to create log analysis prompt", e);
                    throw new RuntimeException("Failed to create log analysis prompt", e);
                }
            }
        );
    }

    public McpSchema.Prompt getThreatAssessmentPrompt() {
        return new McpSchema.Prompt(
            "assess_threat_level",
            "Assess the threat level of detected security events",
            List.of(
                new McpSchema.PromptArgument(
                    "event_data",
                    "Security event data to assess",
                    true
                ),
                new McpSchema.PromptArgument(
                    "context",
                    "Additional context about the environment",
                    false
                ),
                new McpSchema.PromptArgument(
                    "historical_data",
                    "Include historical threat data",
                    false
                )
            )
        );
    }

    public McpServerFeatures.SyncPromptSpecification createThreatAssessmentSpec() {
        return new McpServerFeatures.SyncPromptSpecification(
            getThreatAssessmentPrompt(),
            (exchange, request) -> {
                try {
                    Map<String, Object> args = request.arguments();
                    String eventData = (String) args.get("event_data");
                    String context = (String) args.getOrDefault("context", "");
                    boolean includeHistory = Boolean.parseBoolean(
                        args.getOrDefault("historical_data", "false").toString()
                    );
                    
                    List<McpSchema.PromptMessage> messages = new ArrayList<>();
                    
                    messages.add(new McpSchema.PromptMessage(
                            McpSchema.Role.ASSISTANT,
                        new McpSchema.TextContent(
                            "You are a security threat assessment expert. " +
                            "Analyze the provided security event data and assess the threat level. " +
                            "Consider factors like severity, potential impact, likelihood of exploitation, " +
                            "and recommended mitigation steps."
                        )
                    ));
                    
                    String userPrompt = String.format(
                        "Assess the following security event:\n\n%s\n\n" +
                        "Context: %s\n" +
                        "Historical analysis: %s\n\n" +
                        "Provide:\n" +
                        "1. Threat level (Critical/High/Medium/Low)\n" +
                        "2. Potential impact analysis\n" +
                        "3. Likelihood of exploitation\n" +
                        "4. Recommended immediate actions\n" +
                        "5. Long-term mitigation strategies",
                        eventData,
                        context.isEmpty() ? "Standard enterprise environment" : context,
                        includeHistory ? "Include historical pattern analysis" : "Focus on current event"
                    );
                    
                    messages.add(new McpSchema.PromptMessage(
                            McpSchema.Role.USER,
                        new McpSchema.TextContent(userPrompt)
                    ));
                    
                    return new McpSchema.GetPromptResult(
                        "Threat assessment prompt for security event",
                        messages
                    );
                    
                } catch (Exception e) {
                    log.error("Failed to create threat assessment prompt", e);
                    throw new RuntimeException("Failed to create threat assessment prompt", e);
                }
            }
        );
    }

    private String buildSystemPrompt() {
        return """
            You are an expert security analyst specializing in log analysis and threat detection.
            Your role is to:
            1. Identify security threats, anomalies, and suspicious patterns in logs
            2. Correlate events across different log sources
            3. Provide actionable insights and recommendations
            4. Prioritize findings based on severity and potential impact
            5. Suggest immediate remediation steps
            
            Use industry best practices and frameworks like MITRE ATT&CK for threat categorization.
            Be specific, technical, and action-oriented in your analysis.
            """;
    }

    private String buildUserPrompt(String logType, String timeRange, String severityFilter, String focusArea) {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        
        return String.format("""
            Analyze the following security logs:
            
            Log Type: %s
            Time Range: %s (Current time: %s)
            Severity Filter: %s
            Focus Area: %s
            
            Please provide:
            1. Executive Summary of findings
            2. Detailed threat analysis with evidence
            3. Risk assessment and impact analysis
            4. Recommended immediate actions
            5. Long-term security improvements
            6. Indicators of Compromise (IoCs) identified
            7. MITRE ATT&CK techniques observed
            
            Format your response in a structured manner with clear sections.
            """,
            logType,
            timeRange,
            now.format(formatter),
            severityFilter,
            focusArea
        );
    }

    private String buildAssistantHint(String logType) {
        return String.format(
            "I'll analyze the %s logs focusing on security threats and anomalies. " +
            "Let me examine the patterns and provide a comprehensive security assessment...",
            logType
        );
    }
}