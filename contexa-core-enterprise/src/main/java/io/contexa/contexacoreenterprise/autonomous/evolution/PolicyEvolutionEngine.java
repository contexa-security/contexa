package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.domain.LearningMetadata;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacoreenterprise.autonomous.validation.SpelValidationService;
import io.contexa.contexacoreenterprise.dashboard.metrics.evolution.EvolutionMetricsCollector;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import io.contexa.contexacoreenterprise.properties.PolicyEvolutionProperties;
import org.springframework.beans.factory.annotation.Autowired;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;

@Slf4j
@RequiredArgsConstructor
public class PolicyEvolutionEngine {

    private static final Pattern SPEL_CODE_BLOCK_PATTERN = Pattern.compile(
            "```(?:spel|java)?\\s*([^`]+)```", Pattern.DOTALL);
    private static final Pattern INLINE_CODE_PATTERN = Pattern.compile("`([^`]+)`");
    private static final Pattern NUMERIC_IMPACT_PATTERN = Pattern.compile(
            "(?:영향도|효과|impact|effectiveness|score)\\s*[:=]\\s*(0\\.\\d+|1\\.0)", Pattern.CASE_INSENSITIVE);
    private static final Pattern DECIMAL_VALUE_PATTERN = Pattern.compile("\\b(0\\.[0-9]{1,2})\\b");
    private static final Pattern PERCENTAGE_IMPACT_PATTERN = Pattern.compile(
            "(?:영향도|효과|impact|effectiveness)\\s*[:=]?\\s*(\\d{1,3})%", Pattern.CASE_INSENSITIVE);
    private static final Pattern CONFIDENCE_SCORE_PATTERN = Pattern.compile(
            "(?:신뢰도|confidence)\\s*[:=]\\s*(0\\.\\d+|1\\.0)", Pattern.CASE_INSENSITIVE);

    private final ChatModel chatModel;
    private final UnifiedVectorService unifiedVectorService;

    @Autowired(required = false)
    private EvolutionMetricsCollector metricsCollector;

    private final PolicyEvolutionProperties policyEvolutionProperties;

    @Autowired(required = false)
    private SpelValidationService spelValidationService;

    public PolicyEvolutionProposal evolvePolicy(SecurityEvent event, LearningMetadata metadata) {
        long startTime = System.currentTimeMillis();
        
        try {

            Map<String, Object> context = collectContext(event, metadata);

            List<Document> similarCases = searchSimilarCases(event, metadata);

            if (metricsCollector != null) {
                metricsCollector.recordSimilarCasesFound(similarCases.size());
            }

            PolicyEvolutionProposal proposal = generateProposal(event, metadata, context, similarCases);

            if (proposal.getConfidenceScore() == null) {
                proposal.setConfidenceScore(0.5);
            }
            proposal.setRiskLevel(PolicyEvolutionProposal.RiskLevel.MEDIUM);

            storeLearningData(event, metadata, proposal);

            long duration = System.currentTimeMillis() - startTime;

            if (metricsCollector != null) {
                metricsCollector.recordProposalCreation(
                    duration,
                    proposal.getProposalType().name(),
                    proposal.getRiskLevel().name(),
                    proposal.getConfidenceScore()
                );

                Map<String, Object> eventMetadata = new HashMap<>();
                eventMetadata.put("proposal_type", proposal.getProposalType().name());
                eventMetadata.put("risk_level", proposal.getRiskLevel().name());
                eventMetadata.put("confidence_score", proposal.getConfidenceScore());
                eventMetadata.put("duration", duration);
                metricsCollector.recordEvent("proposal_created", eventMetadata);
            }

            return proposal;

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("Policy evolution failed - EventId: {}", event.getEventId(), e);

            if (metricsCollector != null) {
                metricsCollector.recordProposalCreation(
                    duration,
                    "FAILURE",
                    "UNKNOWN",
                    0.0
                );
            }

            return createFailureProposal(event, metadata, e);
        }
    }

    public PolicyEvolutionProposal evolvePolicy(io.contexa.contexacore.domain.SoarIncidentDto incident, LearningMetadata metadata) {

        SecurityEvent event = convertSoarIncidentToSecurityEvent(incident);

        return evolvePolicy(event, metadata);
    }

    private SecurityEvent convertSoarIncidentToSecurityEvent(io.contexa.contexacore.domain.SoarIncidentDto incident) {
        SecurityEvent.Severity severity = mapIncidentSeverityToEventSeverity(incident.getSeverity());

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("incidentId", incident.getIncidentId());
        metadata.put("incidentTitle", incident.getTitle());
        metadata.put("incidentStatus", incident.getStatus());
        metadata.put("threatType", incident.getThreatType());
        metadata.put("reporter", incident.getReporter());
        metadata.put("assignee", incident.getAssignee());
        metadata.put("detectedAt", incident.getDetectedAt());
        metadata.put("reportedAt", incident.getReportedAt());
        
        if (incident.getType() != null) {
            metadata.put("incidentType", incident.getType().name());
        }

        if (incident.getAffectedAssets() != null) {
            metadata.put("affectedAssets", incident.getAffectedAssets());
        }
        if (incident.getIndicators() != null) {
            metadata.put("indicators", incident.getIndicators());
        }
        if (incident.getEvidence() != null) {
            metadata.put("evidence", incident.getEvidence());
        }
        if (incident.getActionsTaken() != null) {
            metadata.put("actionsTaken", incident.getActionsTaken());
        }

        return SecurityEvent.builder()
            .eventId(incident.getIncidentId())
            .severity(severity)
            .description(incident.getDescription())
            .timestamp(incident.getCreatedAt() != null ? incident.getCreatedAt() : LocalDateTime.now())
            .source(SecurityEvent.EventSource.SIEM)  
            .metadata(metadata)
            .build();
    }

    private SecurityEvent.Severity mapIncidentSeverityToEventSeverity(io.contexa.contexacore.domain.SoarIncidentDto.IncidentSeverity incidentSeverity) {
        if (incidentSeverity == null) {
            return SecurityEvent.Severity.MEDIUM;
        }

        return switch (incidentSeverity) {
            case CRITICAL -> SecurityEvent.Severity.CRITICAL;
            case HIGH -> SecurityEvent.Severity.HIGH;
            case MEDIUM -> SecurityEvent.Severity.MEDIUM;
            case LOW -> SecurityEvent.Severity.LOW;
            case INFO -> SecurityEvent.Severity.INFO;
            default -> SecurityEvent.Severity.MEDIUM;
        };
    }

    public Mono<PolicyEvolutionProposal> evolvePolicyAsync(SecurityEvent event, LearningMetadata metadata) {
        return Mono.fromCallable(() -> evolvePolicy(event, metadata))
                .doOnError(e -> log.error("Async policy evolution failed", e));
    }

    private Map<String, Object> collectContext(SecurityEvent event, LearningMetadata metadata) {
        Map<String, Object> context = new HashMap<>();

        context.put("severity", event.getSeverity());
        context.put("source", event.getSource());
        context.put("timestamp", event.getTimestamp());

        if (event.getSourceIp() != null) {
            context.put("sourceIp", event.getSourceIp());
            
        }

        if (event.getUserId() != null) {
            context.put("userId", event.getUserId());
            context.put("userName", event.getUserName());
        }

        context.putAll(metadata.getLearningContext());
        
        return context;
    }

    private List<Document> searchSimilarCases(SecurityEvent event, LearningMetadata metadata) {
        try {
            String query = buildSearchQuery(event, metadata);

            SearchRequest searchRequest = SearchRequest.builder()
                .query(query)
                .topK(policyEvolutionProperties.getMax().getContextSize())
                .similarityThreshold(0.7)
                .build();
            List<Document> documents = unifiedVectorService.searchSimilar(searchRequest);

            if (documents.size() > policyEvolutionProperties.getMax().getContextSize()) {
                documents = documents.subList(0, policyEvolutionProperties.getMax().getContextSize());
            }
            
                        return documents;
            
        } catch (Exception e) {
            log.error("Similar case search failed: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    private PolicyEvolutionProposal generateProposal(
            SecurityEvent event,
            LearningMetadata metadata,
            Map<String, Object> context,
            List<Document> similarCases) {

        String systemPrompt = buildSystemPrompt();
        String userPrompt = buildUserPrompt(event, metadata, context, similarCases);

        String aiResponse = callAI(systemPrompt, userPrompt);

        PolicyEvolutionProposal proposal = parseAIResponse(aiResponse, event, metadata);

        proposal.setSourceEventId(event.getEventId());
        proposal.setAnalysisLabId(metadata.getSourceLabId());
        proposal.setLearningType(metadata.getLearningType());
        proposal.setCreatedAt(LocalDateTime.now());
        proposal.setEvidenceContext(context);
        
        return proposal;
    }

    private String buildSystemPrompt() {
        StringBuilder sb = new StringBuilder();
        sb.append("You are a security policy SpEL expression generator.\n");
        sb.append("Analyze security events and generate Spring Expression Language (SpEL) authorization policies.\n\n");

        sb.append("# Available SpEL API\n");
        if (spelValidationService != null) {
            sb.append(spelValidationService.generateApiDocumentation());
        }

        sb.append("\n# Rules\n");
        sb.append("1. Use ONLY the methods listed above. Any unlisted method will be rejected.\n");
        sb.append("2. Prefer Hot Path (#trust) for fast authorization (<5ms).\n");
        sb.append("3. Use Cold Path (#ai) ONLY for high-risk operations.\n");
        sb.append("4. Combine with Spring Security methods using 'and'/'or' operators.\n");
        sb.append("5. Keep expressions simple - avoid more than 3 conditions.\n");

        sb.append("\n# Response Format\n");
        sb.append("```spel\n");
        sb.append("// Your SpEL expression here\n");
        sb.append("```\n");
        sb.append("Target Resource: <URL pattern to apply>\n");
        sb.append("HTTP Method: <GET|POST|PUT|DELETE|ALL>\n");
        sb.append("Confidence: <0.0-1.0>\n");
        sb.append("Expected Impact: <0.0-1.0>\n");

        return sb.toString();
    }

    private String buildUserPrompt(
            SecurityEvent event,
            LearningMetadata metadata,
            Map<String, Object> context,
            List<Document> similarCases) {

        StringBuilder prompt = new StringBuilder();
        prompt.append("Analyze the following security event and generate a policy proposal.\n\n");

        prompt.append("## Security Event\n");
        prompt.append(String.format("- Severity: %s\n", event.getSeverity()));
        prompt.append(String.format("- Source: %s\n", event.getSource()));
        prompt.append(String.format("- Description: %s\n", event.getDescription()));

        prompt.append("\n## Learning Type\n");
        prompt.append(String.format("- %s\n", metadata.getLearningType()));

        if (context.containsKey("action")) {
            prompt.append("\n## Threat Analysis Result\n");
            prompt.append(String.format("- Verdict: %s\n", context.get("action")));
            prompt.append(String.format("- Risk Score: %s\n", context.get("riskScore")));
            prompt.append(String.format("- Confidence: %s\n", context.get("confidence")));
            if (context.get("reasoning") != null) {
                prompt.append(String.format("- Reasoning: %s\n", context.get("reasoning")));
            }
            if (context.get("mitre") != null) {
                prompt.append(String.format("- MITRE ATT&CK: %s\n", context.get("mitre")));
            }
            prompt.append(String.format("- Analysis Layer: %s\n", context.get("layerName")));
        }

        String targetResource = extractStringFromMap(context, "targetResource");
        String requestMethod = extractStringFromMap(context, "requestMethod");
        if (targetResource != null || requestMethod != null) {
            prompt.append("\n## Target Resource\n");
            if (targetResource != null) {
                prompt.append(String.format("- URL: %s\n", targetResource));
            }
            if (requestMethod != null) {
                prompt.append(String.format("- HTTP Method: %s\n", requestMethod));
            }
        }

        Set<String> threatKeys = Set.of("action", "riskScore", "confidence", "reasoning",
                "mitre", "layerName", "analysisContext", "targetResource", "requestMethod");
        prompt.append("\n## Context\n");
        context.forEach((key, value) -> {
            if (!threatKeys.contains(key) && !(value instanceof Map) && !(value instanceof Collection)) {
                prompt.append(String.format("- %s: %s\n", key, value));
            }
        });

        if (!similarCases.isEmpty()) {
            prompt.append("\n## Similar Cases\n");
            similarCases.stream()
                .limit(3)
                .forEach(doc -> prompt.append(String.format("- %s\n", doc.getText())));
        }

        return prompt.toString();
    }

    private String callAI(String systemPrompt, String userPrompt) {
        long startTime = System.currentTimeMillis();
        try {
            Prompt aiPrompt = new Prompt(List.of(
                new SystemMessage(systemPrompt),
                new UserMessage(userPrompt)
            ));
            ChatResponse response = chatModel.call(aiPrompt);
            String result = response.getResult().getOutput().getText();

            if (metricsCollector != null) {
                long duration = System.currentTimeMillis() - startTime;
                metricsCollector.recordAICall(duration, "chatModel", true);

                Map<String, Object> eventMetadata = new HashMap<>();
                eventMetadata.put("model", "chatModel");
                eventMetadata.put("duration", duration);
                eventMetadata.put("success", true);
                metricsCollector.recordEvent("ai_call_success", eventMetadata);
            }

            return result;
        } catch (Exception e) {
            
            if (metricsCollector != null) {
                long duration = System.currentTimeMillis() - startTime;
                metricsCollector.recordAICall(duration, "chatModel", false);

                Map<String, Object> eventMetadata = new HashMap<>();
                eventMetadata.put("model", "chatModel");
                eventMetadata.put("duration", duration);
                eventMetadata.put("success", false);
                eventMetadata.put("error", e.getMessage());
                metricsCollector.recordEvent("ai_call_failure", eventMetadata);
            }

            log.error("AI call failed", e);
            return "AI analysis failed: " + e.getMessage();
        }
    }

    private PolicyEvolutionProposal parseAIResponse(
            String aiResponse, 
            SecurityEvent event,
            LearningMetadata metadata) {
        
        PolicyEvolutionProposal proposal = PolicyEvolutionProposal.builder()
            .title(generateTitle(event, metadata))
            .description(extractDescription(aiResponse))
            .proposalType(determineProposalType(event, metadata))
            .aiReasoning(aiResponse)
            .spelExpression(extractSpelExpression(aiResponse))
            .expectedImpact(extractExpectedImpact(aiResponse))
            .build();

        Map<String, Object> actionPayload = new HashMap<>();
        actionPayload.put("severity", event.getSeverity());
        actionPayload.put("learningType", metadata.getLearningType());

        // Extract confidence score from AI response
        Double confidence = extractConfidenceScore(aiResponse);
        if (confidence != null) {
            proposal.setConfidenceScore(confidence);
        }

        // Extract target resource from AI response
        String aiTargetResource = extractTargetFromResponse(aiResponse, "Target Resource");
        String aiRequestMethod = extractTargetFromResponse(aiResponse, "HTTP Method");

        // Fallback to SecurityEvent metadata
        if (aiTargetResource == null) {
            aiTargetResource = extractStringFromMap(event.getMetadata(), "targetResource", "requestUri");
        }
        if (aiRequestMethod == null) {
            aiRequestMethod = extractStringFromMap(event.getMetadata(), "requestMethod", "httpMethod");
        }

        if (aiTargetResource != null) {
            actionPayload.put("targetResource", aiTargetResource);
        }
        if (aiRequestMethod != null) {
            actionPayload.put("requestMethod", aiRequestMethod);
        }

        proposal.setActionPayload(actionPayload);
        
        return proposal;
    }

    private String generateTitle(SecurityEvent event, LearningMetadata metadata) {
        return String.format("[%s] %s response policy",
                            metadata.getLearningType(),
                            event.getSeverity());
    }

    private String extractDescription(String aiResponse) {
        
        String[] lines = aiResponse.split("\n");
        if (lines.length > 0) {
            return lines[0].length() > 255 ? lines[0].substring(0, 255) : lines[0];
        }
        return "AI-generated policy proposal";
    }

    private String extractSpelExpression(String aiResponse) {
        if (aiResponse == null || aiResponse.isEmpty()) {
            
            if (metricsCollector != null) {
                metricsCollector.recordSpelExtraction("empty_response", false);
            }
            return "isAuthenticated()";
        }

        try {
            
            String spelExpression = extractFromCodeBlock(aiResponse);
            if (spelExpression != null) {
                
                if (metricsCollector != null) {
                    metricsCollector.recordSpelExtraction("code_block", true);
                }
                return spelExpression;
            }

            spelExpression = extractSpelFunctionPattern(aiResponse);
            if (spelExpression != null) {

                if (metricsCollector != null) {
                    metricsCollector.recordSpelExtraction("function_pattern", true);
                }
                return spelExpression;
            }

        } catch (Exception e) {
            log.error("SpEL expression extraction failed, using default: {}", e.getMessage());
        }

        if (metricsCollector != null) {
            metricsCollector.recordSpelExtraction("fallback_default", false);
        }

        return "isAuthenticated()";
    }

    private String extractFromCodeBlock(String aiResponse) {
        java.util.regex.Matcher matcher = SPEL_CODE_BLOCK_PATTERN.matcher(aiResponse);
        if (matcher.find()) {
            String code = matcher.group(1).trim();
            if (validateSpelWithService(code)) {
                return code;
            }
        }

        matcher = INLINE_CODE_PATTERN.matcher(aiResponse);
        while (matcher.find()) {
            String code = matcher.group(1).trim();
            if (validateSpelWithService(code)) {
                return code;
            }
        }

        return null;
    }

    private boolean validateSpelWithService(String expression) {
        if (spelValidationService != null) {
            SpelValidationService.ValidationResult result = spelValidationService.validate(expression);
            if (!result.valid()) {
                log.error("AI-generated SpEL validation failed: {}, errors: {}", expression, result.errors());
                return false;
            }
            return true;
        }

        log.error("SpEL validation service not available - rejecting expression: {}", expression);
        return false;
    }

    private static final Pattern[] SPEL_FUNCTION_PATTERNS = {
        Pattern.compile("#ai\\.\\w+\\([^)]*\\)[^\\n]*"),
        Pattern.compile("hasRole\\([^)]+\\)[^\\n]*"),
        Pattern.compile("hasAuthority\\([^)]+\\)[^\\n]*"),
        Pattern.compile("hasAnyRole\\([^)]+\\)[^\\n]*"),
        Pattern.compile("hasAnyAuthority\\([^)]+\\)[^\\n]*"),
        Pattern.compile("permitAll\\(\\)[^\\n]*"),
        Pattern.compile("denyAll\\(\\)[^\\n]*"),
        Pattern.compile("isAuthenticated\\(\\)[^\\n]*"),
        Pattern.compile("isAnonymous\\(\\)[^\\n]*")
    };

    private String extractSpelFunctionPattern(String aiResponse) {
        for (Pattern spelPattern : SPEL_FUNCTION_PATTERNS) {
            java.util.regex.Matcher matcher = spelPattern.matcher(aiResponse);
            if (matcher.find()) {
                String expression = matcher.group(0).trim();
                
                expression = expression.replaceAll("[.!?;]$", "");
                
                if (validateSpelWithService(expression)) {
                    return expression;
                }
            }
        }

        return null;
    }

    private Double extractExpectedImpact(String aiResponse) {
        if (aiResponse == null || aiResponse.isEmpty()) {
            return 0.7; 
        }

        try {
            
            Double impact = extractNumericImpact(aiResponse);
            if (impact != null) {
                return impact;
            }

            impact = extractPercentageImpact(aiResponse);
            if (impact != null) {
                return impact;
            }

            impact = extractTextualImpact(aiResponse);
            if (impact != null) {
                return impact;
            }

        } catch (Exception e) {
            log.error("Impact extraction failed, using default: {}", e.getMessage());
        }

        return 0.7; 
    }

    private Double extractNumericImpact(String aiResponse) {
        java.util.regex.Matcher matcher = NUMERIC_IMPACT_PATTERN.matcher(aiResponse);

        if (matcher.find()) {
            try {
                double value = Double.parseDouble(matcher.group(1));
                if (value >= 0.0 && value <= 1.0) {
                    return value;
                }
            } catch (NumberFormatException e) {
                            }
        }

        matcher = DECIMAL_VALUE_PATTERN.matcher(aiResponse);

        while (matcher.find()) {
            try {
                double value = Double.parseDouble(matcher.group(1));
                
                if (value >= 0.0 && value <= 1.0) {
                    return value;
                }
            } catch (NumberFormatException e) {
                
            }
        }

        return null;
    }

    private Double extractPercentageImpact(String aiResponse) {
        java.util.regex.Matcher matcher = PERCENTAGE_IMPACT_PATTERN.matcher(aiResponse);

        if (matcher.find()) {
            try {
                int percentage = Integer.parseInt(matcher.group(1));
                if (percentage >= 0 && percentage <= 100) {
                    return percentage / 100.0;
                }
            } catch (NumberFormatException e) {
                            }
        }

        return null;
    }

    private Double extractTextualImpact(String aiResponse) {
        String lowerResponse = aiResponse.toLowerCase();

        if (lowerResponse.contains("매우 높") || lowerResponse.contains("very high") ||
            lowerResponse.contains("excellent") || lowerResponse.contains("탁월")) {
            return 0.9;
        }

        if (lowerResponse.contains("높은") || lowerResponse.contains("high") ||
            lowerResponse.contains("significant") || lowerResponse.contains("상당")) {
            return 0.8;
        }

        if (lowerResponse.contains("중상") || lowerResponse.contains("moderate-high") ||
            lowerResponse.contains("good")) {
            return 0.7;
        }

        if (lowerResponse.contains("중간") || lowerResponse.contains("medium") ||
            lowerResponse.contains("moderate") || lowerResponse.contains("보통")) {
            return 0.6;
        }

        if (lowerResponse.contains("중하") || lowerResponse.contains("moderate-low") ||
            lowerResponse.contains("fair")) {
            return 0.5;
        }

        if (lowerResponse.contains("낮은") || lowerResponse.contains("low") ||
            lowerResponse.contains("minor") || lowerResponse.contains("적은")) {
            return 0.4;
        }

        if (lowerResponse.contains("매우 낮") || lowerResponse.contains("very low") ||
            lowerResponse.contains("minimal") || lowerResponse.contains("미미")) {
            return 0.3;
        }

        return null;
    }

    private Double extractConfidenceScore(String aiResponse) {
        if (aiResponse == null || aiResponse.isEmpty()) {
            return null;
        }
        java.util.regex.Matcher matcher = CONFIDENCE_SCORE_PATTERN.matcher(aiResponse);
        if (matcher.find()) {
            try {
                double value = Double.parseDouble(matcher.group(1));
                if (value >= 0.0 && value <= 1.0) {
                    return value;
                }
            } catch (NumberFormatException e) {
                // fall through to return null
            }
        }
        return null;
    }

    private String extractTargetFromResponse(String aiResponse, String label) {
        if (aiResponse == null) {
            return null;
        }
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                label + "\\s*[::]\\s*(.+?)(?:\\n|$)");
        java.util.regex.Matcher matcher = pattern.matcher(aiResponse);
        if (matcher.find()) {
            String value = matcher.group(1).trim();
            if (!value.isEmpty() && !value.startsWith("<")) {
                return value;
            }
        }
        return null;
    }

    private String extractStringFromMap(Map<String, Object> map, String... keys) {
        if (map == null) {
            return null;
        }
        for (String key : keys) {
            Object value = map.get(key);
            if (value instanceof String str && !str.isEmpty()) {
                return str;
            }
        }
        return null;
    }

    private PolicyEvolutionProposal.ProposalType determineProposalType(
            SecurityEvent event, 
            LearningMetadata metadata) {

        return switch (metadata.getLearningType()) {
            case THREAT_RESPONSE -> PolicyEvolutionProposal.ProposalType.CREATE_POLICY;
            case ACCESS_PATTERN -> PolicyEvolutionProposal.ProposalType.OPTIMIZE_RULE;
            case POLICY_FEEDBACK -> PolicyEvolutionProposal.ProposalType.UPDATE_POLICY;
            case FALSE_POSITIVE_LEARNING -> PolicyEvolutionProposal.ProposalType.ADJUST_THRESHOLD;
            case COMPLIANCE_LEARNING -> PolicyEvolutionProposal.ProposalType.CREATE_POLICY;
            default -> PolicyEvolutionProposal.ProposalType.SUGGEST_TRAINING;
        };
    }

    private void storeLearningData(
            SecurityEvent event,
            LearningMetadata metadata,
            PolicyEvolutionProposal proposal) {
        
        try {
            
            Map<String, Object> documentMetadata = new HashMap<>();
            documentMetadata.put("eventId", event.getEventId());
            documentMetadata.put("learningType", metadata.getLearningType());
            documentMetadata.put("proposalType", proposal.getProposalType());
            documentMetadata.put("confidence", proposal.getConfidenceScore());
            documentMetadata.put("timestamp", LocalDateTime.now());
            
            Document document = new Document(
                proposal.getAiReasoning(),
                documentMetadata
            );

            unifiedVectorService.storeDocument(document);

        } catch (Exception e) {
            log.error("Learning data storage failed: {}", e.getMessage());
        }
    }

    private String buildSearchQuery(SecurityEvent event, LearningMetadata metadata) {
        return String.format("%s %s %s %s",
                            event.getSeverity(),
                            event.getSource(),
                            metadata.getLearningType(),
                            event.getDescription() != null ? event.getDescription() : "");
    }

    private PolicyEvolutionProposal createFailureProposal(
            SecurityEvent event,
            LearningMetadata metadata,
            Exception e) {
        
        return PolicyEvolutionProposal.builder()
            .title("Policy evolution failed")
            .description("Unable to generate policy proposal due to error: " + e.getMessage())
            .proposalType(PolicyEvolutionProposal.ProposalType.SUGGEST_TRAINING)
            .sourceEventId(event.getEventId())
            .analysisLabId(metadata.getSourceLabId())
            .aiReasoning("Error occurred: " + e.getMessage())
            .confidenceScore(0.0)
            .riskLevel(PolicyEvolutionProposal.RiskLevel.LOW)
            .createdAt(LocalDateTime.now())
            .build();
    }

}