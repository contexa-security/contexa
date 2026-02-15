package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.domain.LearningMetadata;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacoreenterprise.domain.dto.PolicyDTO;
import io.contexa.contexacoreenterprise.autonomous.intelligence.AITuningService;
import io.contexa.contexacoreenterprise.autonomous.validation.SpelValidationService;
import io.contexa.contexacoreenterprise.dashboard.metrics.evolution.EvolutionMetricsCollector;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import io.contexa.contexacoreenterprise.properties.PolicyEvolutionProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
public class PolicyEvolutionEngine {

    private final ChatModel chatModel;
    private final UnifiedVectorService unifiedVectorService;
    private final AITuningService tuningService;

    @Autowired(required = false)
    private EvolutionMetricsCollector metricsCollector;

    private final PolicyEvolutionProperties policyEvolutionProperties;

    @Autowired(required = false)
    private SpelValidationService spelValidationService;

    private final RedisTemplate<String, PolicyEvolutionProposal> redisTemplate;
    private final RedisTemplate<String, String> stringRedisTemplate;

    private static final String PROPOSAL_CACHE_KEY_PREFIX = "policy:evolution:proposal:";
    private static final String PROPOSAL_SET_KEY = "policy:evolution:proposals:all";
    private static final Duration PROPOSAL_CACHE_TTL = Duration.ofHours(1);
    private static final Duration PROPOSAL_LONG_TTL = Duration.ofHours(24);

    public PolicyEvolutionProposal evolvePolicy(SecurityEvent event, LearningMetadata metadata) {
        long startTime = System.currentTimeMillis();
        
        try {
            
            String cacheKey = generateCacheKey(event, metadata);
            if (policyEvolutionProperties.getEnable().isCaching()) {
                PolicyEvolutionProposal cachedProposal = getFromRedisCache(cacheKey);
                if (cachedProposal != null) {
                                        return cachedProposal;
                }
            }

            Map<String, Object> context = collectContext(event, metadata);

            List<Document> similarCases = searchSimilarCases(event, metadata);

            if (metricsCollector != null) {
                metricsCollector.recordSimilarCasesFound(similarCases.size());
            }

            PolicyEvolutionProposal proposal = generateProposal(event, metadata, context, similarCases);

            evaluateConfidence(proposal, context, similarCases);

            assessRiskLevel(proposal, event, metadata);

            if (policyEvolutionProperties.getEnable().isCaching()) {
                saveToRedisCache(cacheKey, proposal);
            }

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

        switch (incidentSeverity) {
            case CRITICAL:
                return SecurityEvent.Severity.CRITICAL;
            case HIGH:
                return SecurityEvent.Severity.HIGH;
            case MEDIUM:
                return SecurityEvent.Severity.MEDIUM;
            case LOW:
                return SecurityEvent.Severity.LOW;
            case INFO:
                return SecurityEvent.Severity.INFO;
            default:
                return SecurityEvent.Severity.MEDIUM;
        }
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

        String prompt = buildEvolutionPrompt(event, metadata, context, similarCases);

        String aiResponse = callAI(prompt);

        PolicyEvolutionProposal proposal = parseAIResponse(aiResponse, event, metadata);

        proposal.setSourceEventId(event.getEventId());
        proposal.setAnalysisLabId(metadata.getSourceLabId());
        proposal.setLearningType(metadata.getLearningType());
        proposal.setCreatedAt(LocalDateTime.now());
        proposal.setEvidenceContext(context);
        
        return proposal;
    }

    private String buildEvolutionPrompt(
            SecurityEvent event,
            LearningMetadata metadata,
            Map<String, Object> context,
            List<Document> similarCases) {
        
        StringBuilder prompt = new StringBuilder();
        prompt.append("보안 이벤트를 분석하여 정책 제안을 생성해주세요.\n\n");

        prompt.append("## 보안 이벤트\n");
        prompt.append(String.format("- 심각도: %s\n", event.getSeverity()));
        prompt.append(String.format("- 출처: %s\n", event.getSource()));
        prompt.append(String.format("- 설명: %s\n", event.getDescription()));

        prompt.append("\n## 학습 유형\n");
        prompt.append(String.format("- %s\n", metadata.getLearningType()));

        prompt.append("\n## 컨텍스트\n");
        context.forEach((key, value) -> 
            prompt.append(String.format("- %s: %s\n", key, value))
        );

        if (!similarCases.isEmpty()) {
            prompt.append("\n## 유사 사례\n");
            similarCases.stream()
                .limit(3)
                .forEach(doc -> prompt.append(String.format("- %s\n", doc.getText())));
        }

        prompt.append("\n## 사용 가능한 SpEL API\n");
        prompt.append("### #trust 변수 (Hot Path - Redis LLM Action 조회, 응답시간 5ms 이내)\n");
        prompt.append("- #trust.isAllowed() : LLM이 ALLOW로 판정했는지 확인\n");
        prompt.append("- #trust.isBlocked() : LLM이 BLOCK으로 판정했는지 확인\n");
        prompt.append("- #trust.needsChallenge() : MFA 추가 인증 필요 여부 (CHALLENGE)\n");
        prompt.append("- #trust.needsInvestigation() : 추가 조사 필요 여부 (INVESTIGATE/ESCALATE)\n");
        prompt.append("- #trust.isMonitored() : 모니터링 모드 여부 (MONITOR)\n");
        prompt.append("- #trust.isPendingAnalysis() : 분석 미완료 여부 (PENDING_ANALYSIS)\n");
        prompt.append("- #trust.hasAction('ACTION') : 특정 LLM action 확인\n");
        prompt.append("- #trust.hasActionIn('ACTION1', 'ACTION2') : 여러 action 중 하나 확인\n");
        prompt.append("- #trust.hasResourceAccess('resourceId', threshold) : 리소스별 접근 권한\n");
        prompt.append("\n### #ai 변수 (Cold Path - 실시간 AI 분석, 고위험 작업 전용)\n");
        prompt.append("- #ai.analyzeFraud(#transaction) : 사기 거래 분석\n");
        prompt.append("- #ai.detectAnomaly('operation') : 이상 행동 탐지\n");
        prompt.append("- #ai.evaluateCriticalOperation(#context) : 중요 작업 평가\n");
        prompt.append("- #ai.hasSafeBehavior(threshold) : 행동 안전성 평가\n");
        prompt.append("- #ai.isAllowed() : ALLOW 판정 확인\n");
        prompt.append("- #ai.isBlocked() : BLOCK 판정 확인\n");
        prompt.append("- #ai.needsChallenge() : CHALLENGE 판정 확인\n");
        prompt.append("- #ai.needsEscalation() : ESCALATE 판정 확인\n");
        prompt.append("- #ai.hasAction('ACTION') : 특정 action 확인\n");
        prompt.append("- #ai.hasActionIn('ACTION1', 'ACTION2') : 여러 action 확인\n");
        prompt.append("\n### Spring Security 기본 메서드\n");
        prompt.append("- hasRole('ROLE_XXX') : 역할 확인\n");
        prompt.append("- hasAnyRole('ROLE_A', 'ROLE_B') : 여러 역할 중 하나 확인\n");
        prompt.append("- hasAuthority('XXX') : 권한 확인\n");
        prompt.append("- hasAnyAuthority('A', 'B') : 여러 권한 중 하나 확인\n");
        prompt.append("- isAuthenticated() : 인증 여부\n");
        prompt.append("- isFullyAuthenticated() : 완전 인증 여부 (Remember-Me 제외)\n");

        prompt.append("\n## 요청사항\n");
        prompt.append("1. 이 이벤트를 예방하기 위한 정책을 제안해주세요.\n");
        prompt.append("2. 위 SpEL API 목록에 있는 메서드만 사용하여 정책을 작성해주세요.\n");
        prompt.append("3. Hot Path(#trust)를 우선 사용하고, 고위험 작업에만 Cold Path(#ai) 사용\n");
        prompt.append("4. 정책의 예상 효과를 0.0-1.0 사이로 평가해주세요.\n");
        prompt.append("5. 정책 적용 시 주의사항을 명시해주세요.\n");

        prompt.append("\n## 응답 형식\n");
        prompt.append("```spel\n");
        prompt.append("// SpEL 표현식을 여기에 작성\n");
        prompt.append("```\n");

        return prompt.toString();
    }

    private String callAI(String prompt) {
        long startTime = System.currentTimeMillis();
        try {
            Prompt aiPrompt = new Prompt(prompt);
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
            return "hasRole('USER') and #request.isSecure()"; 
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

            spelExpression = requestSpelFromAI(aiResponse);
            if (spelExpression != null) {
                
                if (metricsCollector != null) {
                    metricsCollector.recordSpelExtraction("ai_retry", true);
                }
                return spelExpression;
            }

        } catch (Exception e) {
            log.error("SpEL expression extraction failed, using default: {}", e.getMessage());
        }

        if (metricsCollector != null) {
            metricsCollector.recordSpelExtraction("fallback_default", false);
        }

        return "hasRole('USER') and #request.isSecure()";
    }

    private String extractFromCodeBlock(String aiResponse) {
        
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
            "```(?:spel|java)?\\s*([^`]+)```",
            java.util.regex.Pattern.DOTALL
        );
        java.util.regex.Matcher matcher = pattern.matcher(aiResponse);
        if (matcher.find()) {
            String code = matcher.group(1).trim();
            
            if (validateSpelWithService(code)) {
                return code;
            }
        }

        pattern = java.util.regex.Pattern.compile("`([^`]+)`");
        matcher = pattern.matcher(aiResponse);
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

    private String extractSpelFunctionPattern(String aiResponse) {
        
        String[] spelPatterns = {
            "#trust\\.\\w+\\([^)]*\\)[^\\n]*",    
            "#ai\\.\\w+\\([^)]*\\)[^\\n]*",       
            "hasRole\\([^)]+\\)[^\\n]*",
            "hasAuthority\\([^)]+\\)[^\\n]*",
            "hasPermission\\([^)]+\\)[^\\n]*",
            "hasAnyRole\\([^)]+\\)[^\\n]*",
            "hasAnyAuthority\\([^)]+\\)[^\\n]*",
            "permitAll\\(\\)[^\\n]*",
            "denyAll\\(\\)[^\\n]*",
            "isAuthenticated\\(\\)[^\\n]*",
            "isAnonymous\\(\\)[^\\n]*"
        };

        for (String patternStr : spelPatterns) {
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(patternStr);
            java.util.regex.Matcher matcher = pattern.matcher(aiResponse);
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

    private String requestSpelFromAI(String originalResponse) {
        try {
            String extractionPrompt = String.format(
                "다음 텍스트에서 Spring Security SpEL 표현식만 추출해주세요. " +
                "코드 블록이나 설명 없이 SpEL 표현식만 반환해주세요.\n" +
                "허용된 API: #trust.isAllowed(), #trust.isBlocked(), #trust.hasActionIn(), #ai.hasSafeBehavior(), hasRole(), hasAuthority() 등\n\n%s",
                originalResponse.substring(0, Math.min(500, originalResponse.length()))
            );

            Prompt prompt = new Prompt(extractionPrompt);
            ChatResponse response = chatModel.call(prompt);
            String extractedSpel = response.getResult().getOutput().getText().trim();

            if (validateSpelWithService(extractedSpel)) {
                return extractedSpel;
            }

        } catch (Exception e) {
                    }

        return null;
    }

    private boolean isValidSpelExpression(String expression) {
        if (expression == null || expression.isEmpty() || expression.length() > 500) {
            return false;
        }

        String lowerExpression = expression.toLowerCase();
        boolean hasSpelKeyword =
            lowerExpression.contains("hasrole") ||
            lowerExpression.contains("hasauthority") ||
            lowerExpression.contains("haspermission") ||
            lowerExpression.contains("permitall") ||
            lowerExpression.contains("denyall") ||
            lowerExpression.contains("isauthenticated") ||
            lowerExpression.contains("isanonymous") ||
            lowerExpression.contains("principal") ||
            lowerExpression.contains("#") ||  
            lowerExpression.contains("and") ||
            lowerExpression.contains("or");

        boolean hasBalancedParentheses = checkBalancedParentheses(expression);

        return hasSpelKeyword && hasBalancedParentheses;
    }

    private boolean checkBalancedParentheses(String expression) {
        int count = 0;
        for (char c : expression.toCharArray()) {
            if (c == '(') count++;
            else if (c == ')') count--;
            if (count < 0) return false;
        }
        return count == 0;
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

            impact = requestImpactFromAI(aiResponse);
            if (impact != null) {
                return impact;
            }

        } catch (Exception e) {
            log.error("Impact extraction failed, using default: {}", e.getMessage());
        }

        return 0.7; 
    }

    private Double extractNumericImpact(String aiResponse) {
        
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
            "(?:영향도|효과|impact|effectiveness|score)\\s*[:=]\\s*(0\\.\\d+|1\\.0)",
            java.util.regex.Pattern.CASE_INSENSITIVE
        );
        java.util.regex.Matcher matcher = pattern.matcher(aiResponse);

        if (matcher.find()) {
            try {
                double value = Double.parseDouble(matcher.group(1));
                if (value >= 0.0 && value <= 1.0) {
                    return value;
                }
            } catch (NumberFormatException e) {
                            }
        }

        pattern = java.util.regex.Pattern.compile("\\b(0\\.[0-9]{1,2})\\b");
        matcher = pattern.matcher(aiResponse);

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
        
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
            "(?:영향도|효과|impact|effectiveness)\\s*[:=]?\\s*(\\d{1,3})%",
            java.util.regex.Pattern.CASE_INSENSITIVE
        );
        java.util.regex.Matcher matcher = pattern.matcher(aiResponse);

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

    private Double requestImpactFromAI(String originalResponse) {
        try {
            String extractionPrompt = String.format(
                "다음 정책 제안의 예상 영향도를 0.0에서 1.0 사이의 숫자로만 답변해주세요. " +
                "숫자만 반환하고 설명은 포함하지 마세요:\n\n%s",
                originalResponse.substring(0, Math.min(500, originalResponse.length()))
            );

            Prompt prompt = new Prompt(extractionPrompt);
            ChatResponse response = chatModel.call(prompt);
            String impactText = response.getResult().getOutput().getText().trim();

            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("(0\\.\\d+|1\\.0|0|1)");
            java.util.regex.Matcher matcher = pattern.matcher(impactText);

            if (matcher.find()) {
                double value = Double.parseDouble(matcher.group(1));
                if (value >= 0.0 && value <= 1.0) {
                    return value;
                }
            }

        } catch (Exception e) {
                    }

        return null;
    }

    private PolicyEvolutionProposal.ProposalType determineProposalType(
            SecurityEvent event, 
            LearningMetadata metadata) {
        
        switch (metadata.getLearningType()) {
            case THREAT_RESPONSE:
                return PolicyEvolutionProposal.ProposalType.CREATE_POLICY;
            case ACCESS_PATTERN:
                return PolicyEvolutionProposal.ProposalType.OPTIMIZE_RULE;
            case POLICY_FEEDBACK:
                return PolicyEvolutionProposal.ProposalType.UPDATE_POLICY;
            case FALSE_POSITIVE_LEARNING:
                return PolicyEvolutionProposal.ProposalType.ADJUST_THRESHOLD;
            case COMPLIANCE_LEARNING:
                return PolicyEvolutionProposal.ProposalType.CREATE_POLICY;
            default:
                return PolicyEvolutionProposal.ProposalType.SUGGEST_TRAINING;
        }
    }

    private void evaluateConfidence(
            PolicyEvolutionProposal proposal,
            Map<String, Object> context,
            List<Document> similarCases) {
        
        double confidence = 0.5; 

        if (similarCases.size() >= 5) {
            confidence += 0.2;
        } else if (similarCases.size() >= 3) {
            confidence += 0.1;
        }

        if (context.size() >= 10) {
            confidence += 0.2;
        } else if (context.size() >= 5) {
            confidence += 0.1;
        }

        if (proposal.getSpelExpression() != null && !proposal.getSpelExpression().isEmpty()) {
            confidence += 0.1;
        }

        confidence = Math.min(confidence, 1.0);
        
        proposal.setConfidenceScore(confidence);
    }

    private void assessRiskLevel(
            PolicyEvolutionProposal proposal,
            SecurityEvent event,
            LearningMetadata metadata) {
        
        PolicyEvolutionProposal.RiskLevel riskLevel;

        switch (proposal.getProposalType()) {
            case DELETE_POLICY:
            case REVOKE_ACCESS:
                riskLevel = PolicyEvolutionProposal.RiskLevel.HIGH;
                break;
                
            case CREATE_POLICY:
            case UPDATE_POLICY:
                riskLevel = PolicyEvolutionProposal.RiskLevel.MEDIUM;
                break;
                
            case ADJUST_THRESHOLD:
            case OPTIMIZE_RULE:
                if (event.getSeverity().toString().equals("CRITICAL")) {
                    riskLevel = PolicyEvolutionProposal.RiskLevel.HIGH;
                } else {
                    riskLevel = PolicyEvolutionProposal.RiskLevel.MEDIUM;
                }
                break;
                
            case SUGGEST_TRAINING:
            case CREATE_ALERT:
            default:
                riskLevel = PolicyEvolutionProposal.RiskLevel.LOW;
                break;
        }

        if (proposal.getConfidenceScore() < 0.5 && riskLevel == PolicyEvolutionProposal.RiskLevel.LOW) {
            riskLevel = PolicyEvolutionProposal.RiskLevel.MEDIUM;
        }
        
        proposal.setRiskLevel(riskLevel);
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

            AITuningService.UserFeedback feedback = AITuningService.UserFeedback.builder()
                .feedbackType("FALSE_POSITIVE")
                .comment("policy evolution learning")
                .timestamp(LocalDateTime.now())
                .build();
            tuningService.learnFalsePositive(event, feedback).subscribe();

        } catch (Exception e) {
            log.error("Learning data storage failed: {}", e.getMessage());
        }
    }

    private String generateCacheKey(SecurityEvent event, LearningMetadata metadata) {
        return String.format("%s_%s_%s_%s",
                            event.getSeverity(),
                            event.getSource(),
                            metadata.getLearningType(),
                            metadata.getSourceLabId());
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

    private PolicyEvolutionProposal getFromRedisCache(String cacheKey) {
        try {
            String redisKey = PROPOSAL_CACHE_KEY_PREFIX + cacheKey;
            return redisTemplate.opsForValue().get(redisKey);
        } catch (Exception e) {
            log.error("Redis cache lookup failed: key={}", cacheKey, e);
            return null;
        }
    }

    private void saveToRedisCache(String cacheKey, PolicyEvolutionProposal proposal) {
        try {
            String redisKey = PROPOSAL_CACHE_KEY_PREFIX + cacheKey;
            
            Duration ttl = PROPOSAL_CACHE_TTL;
            
            redisTemplate.opsForValue().set(redisKey, proposal, ttl);

            stringRedisTemplate.opsForSet().add(PROPOSAL_SET_KEY, cacheKey);
            
                    } catch (Exception e) {
            log.error("Redis cache save failed: key={}", cacheKey, e);
        }
    }

    public void clearCache() {
        try {
            
            var keys = stringRedisTemplate.opsForSet().members(PROPOSAL_SET_KEY);
            if (keys != null && !keys.isEmpty()) {
                for (String key : keys) {
                    String redisKey = PROPOSAL_CACHE_KEY_PREFIX + key;
                    redisTemplate.delete(redisKey);
                }
                stringRedisTemplate.delete(PROPOSAL_SET_KEY);
            }
                    } catch (Exception e) {
            log.error("Redis cache cleanup failed", e);
        }
    }

    public int getCacheSize() {
        try {
            Long size = stringRedisTemplate.opsForSet().size(PROPOSAL_SET_KEY);
            return size != null ? size.intValue() : 0;
        } catch (Exception e) {
            log.error("Redis cache size query failed", e);
            return 0;
        }
    }

    public void invalidateProposal(String proposalId) {
        try {
            String pattern = PROPOSAL_CACHE_KEY_PREFIX + "*" + proposalId + "*";
            var keys = redisTemplate.keys(pattern);
            if (keys != null && !keys.isEmpty()) {
                redisTemplate.delete(keys);
                            }
        } catch (Exception e) {
            log.error("Proposal invalidation failed: proposalId={}", proposalId, e);
        }
    }

    public List<PolicyEvolutionProposal> getAllCachedProposals() {
        List<PolicyEvolutionProposal> proposals = new ArrayList<>();
        try {
            var keys = stringRedisTemplate.opsForSet().members(PROPOSAL_SET_KEY);
            if (keys != null) {
                for (String key : keys) {
                    String redisKey = PROPOSAL_CACHE_KEY_PREFIX + key;
                    PolicyEvolutionProposal proposal = redisTemplate.opsForValue().get(redisKey);
                    if (proposal != null) {
                        proposals.add(proposal);
                    }
                }
            }
                    } catch (Exception e) {
            log.error("Cached proposal retrieval failed", e);
        }
        return proposals;
    }

    public void learnFromRejection(PolicyDTO policy, String rejectionReason) {
        
        try {
            
            Map<String, Object> rejectionContext = new HashMap<>();
            rejectionContext.put("policyId", policy.getId());
            rejectionContext.put("policyName", policy.getName());
            rejectionContext.put("policySource", policy.getSource());
            rejectionContext.put("confidenceScore", policy.getConfidenceScore());
            rejectionContext.put("aiModel", policy.getAiModel());
            rejectionContext.put("rejectionReason", rejectionReason);
            rejectionContext.put("rejectedAt", LocalDateTime.now());

            Document rejectionDoc = new Document(
                "REJECTION: Policy=" + policy.getName() + ", Reason=" + rejectionReason,
                rejectionContext
            );
            rejectionDoc.getMetadata().put("type", "policy_rejection");
            rejectionDoc.getMetadata().put("policyId", policy.getId());

            List<Document> docs = Collections.singletonList(rejectionDoc);
            for (Document doc : docs) {
                unifiedVectorService.storeDocument(doc);
            }

            LearningMetadata metadata = LearningMetadata.builder()
                .learningType(LearningMetadata.LearningType.POLICY_FEEDBACK)
                .isLearnable(true)
                .confidenceScore(0.3) 
                .sourceLabId("PolicyEvolutionEngine")
                .priority(7)
                .status(LearningMetadata.LearningStatus.COMPLETED)
                .learningSummary("Policy rejected: " + rejectionReason)
                .build();

            metadata.addPattern("rejection_reason", rejectionReason);
            metadata.addOutcome("learned", true);

        } catch (Exception e) {
            log.error("Rejection learning failed: {}", policy.getName(), e);
        }
    }

    public void requestEvolution(PolicyDTO policy, Map<String, Object> context) {
        
        try {

            SecurityEvent event = SecurityEvent.builder()
                .source(SecurityEvent.EventSource.IAM)
                .severity(SecurityEvent.Severity.MEDIUM)
                .description("Policy evolution requested: " + policy.getName())
                .metadata(context)
                .build();

            LearningMetadata metadata = LearningMetadata.builder()
                .learningType(LearningMetadata.LearningType.POLICY_FEEDBACK)
                .isLearnable(true)
                .confidenceScore(policy.getConfidenceScore() != null ? policy.getConfidenceScore() : 0.5)
                .sourceLabId("PolicyEvolutionEngine")
                .priority(8)
                .status(LearningMetadata.LearningStatus.PENDING)
                .build();

            metadata.addContext("originalPolicyId", policy.getId());
            metadata.addContext("originalPolicyName", policy.getName());
            metadata.addContext("evolutionReason", context.get("changeReason"));

            PolicyEvolutionProposal proposal = evolvePolicy(event, metadata);

            if (proposal != null && proposal.getConfidenceScore() > 0.7) {
                createEvolvedPolicy(policy, proposal);
            }

        } catch (Exception e) {
            log.error("Policy evolution failed: {}", policy.getName(), e);
        }
    }

    // TODO: Implement post-processing for evolved policy creation
    private void createEvolvedPolicy(PolicyDTO originalPolicy,
                                    PolicyEvolutionProposal proposal) {

        Map<String, Object> evolutionData = new HashMap<>();
        evolutionData.put("originalPolicy", originalPolicy);
        evolutionData.put("proposal", proposal);
        evolutionData.put("evolvedAt", LocalDateTime.now());

        log.error("createEvolvedPolicy not yet implemented - originalPolicy: {}, proposal: {}",
                  originalPolicy.getName(), proposal.getTitle());
    }
}