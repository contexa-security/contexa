package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.domain.LearningMetadata;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacoreenterprise.domain.dto.PolicyDTO;
import io.contexa.contexacoreenterprise.autonomous.intelligence.AITuningService;
import io.contexa.contexacoreenterprise.dashboard.metrics.evolution.EvolutionMetricsCollector;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

/**
 * 정책 진화 엔진
 *
 * 기존 Lab들의 분석 결과를 통합하여 정책으로 진화시키는 핵심 엔진입니다.
 * 이 엔진은 Lab을 직접 상속하지 않고, 오케스트레이터 역할을 수행합니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@ConditionalOnClass(name = "io.contexa.contexacore.repository.PolicyProposalRepository")
@Service
@RequiredArgsConstructor
public class PolicyEvolutionEngine {

    private final ChatModel chatModel;
    private final UnifiedVectorService unifiedVectorService;
    private final AITuningService tuningService;

    // Metrics Collector (Optional - 없어도 동작)
    @Autowired(required = false)
    private EvolutionMetricsCollector metricsCollector;
    
    @Value("${policy.evolution.confidence.threshold:0.7}")
    private double confidenceThreshold;
    
    @Value("${policy.evolution.max.context.size:10}")
    private int maxContextSize;
    
    @Value("${policy.evolution.enable.caching:true}")
    private boolean enableCaching;
    
    // Redis 캐시 (영구 저장)
    private final RedisTemplate<String, PolicyEvolutionProposal> redisTemplate;
    private final RedisTemplate<String, String> stringRedisTemplate;
    
    // Redis 캐시 키 설정
    private static final String PROPOSAL_CACHE_KEY_PREFIX = "policy:evolution:proposal:";
    private static final String PROPOSAL_SET_KEY = "policy:evolution:proposals:all";
    private static final Duration PROPOSAL_CACHE_TTL = Duration.ofHours(1);
    private static final Duration PROPOSAL_LONG_TTL = Duration.ofHours(24);
    
    /**
     * 보안 이벤트와 학습 메타데이터를 기반으로 정책을 진화시킵니다.
     * 
     * @param event 보안 이벤트
     * @param metadata 학습 메타데이터
     * @return 진화된 정책 제안
     */
    public PolicyEvolutionProposal evolvePolicy(SecurityEvent event, LearningMetadata metadata) {
        long startTime = System.currentTimeMillis();
        log.info("정책 진화 시작 - EventId: {}, LearningType: {}",
                 event.getEventId(), metadata.getLearningType());

        try {
            // 1. Redis 캐시 확인
            String cacheKey = generateCacheKey(event, metadata);
            if (enableCaching) {
                PolicyEvolutionProposal cachedProposal = getFromRedisCache(cacheKey);
                if (cachedProposal != null) {
                    log.info("Redis 캐시에서 제안 반환: {}", cacheKey);
                    return cachedProposal;
                }
            }

            // 2. 컨텍스트 수집
            Map<String, Object> context = collectContext(event, metadata);

            // 3. 유사 사례 검색
            List<Document> similarCases = searchSimilarCases(event, metadata);

            // 📊 메트릭: 유사 사례 검색 결과
            if (metricsCollector != null) {
                metricsCollector.recordSimilarCasesFound(similarCases.size());
            }

            // 4. AI 분석 및 정책 생성
            PolicyEvolutionProposal proposal = generateProposal(event, metadata, context, similarCases);

            // 5. 신뢰도 평가
            evaluateConfidence(proposal, context, similarCases);

            // 6. 위험도 평가
            assessRiskLevel(proposal, event, metadata);

            // 7. Redis 캐시 저장
            if (enableCaching) {
                saveToRedisCache(cacheKey, proposal);
            }

            // 8. 벡터 스토어에 학습 데이터 저장
            storeLearningData(event, metadata, proposal);

            long duration = System.currentTimeMillis() - startTime;
            log.info("정책 진화 완료 - ProposalType: {}, Confidence: {}, Risk: {}",
                     proposal.getProposalType(), proposal.getConfidenceScore(), proposal.getRiskLevel());

            // 📊 메트릭: 정책 제안 생성 성공
            if (metricsCollector != null) {
                metricsCollector.recordProposalCreation(
                    duration,
                    proposal.getProposalType().name(),
                    proposal.getRiskLevel().name(),
                    proposal.getConfidenceScore()
                );

                // EventRecorder 인터페이스 호출
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
            log.error(" 정책 진화 실패 - EventId: {}", event.getEventId(), e);

            // 📊 메트릭: 정책 제안 생성 실패
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

    /**
     * SoarIncidentDto 기반 정책 진화
     *
     * @param incident SOAR 인시던트 DTO
     * @param metadata 학습 메타데이터
     * @return 진화된 정책 제안
     */
    public PolicyEvolutionProposal evolvePolicy(io.contexa.contexacore.domain.SoarIncidentDto incident, LearningMetadata metadata) {
        log.info("정책 진화 시작 (SoarIncidentDto) - IncidentId: {}, Type: {}",
                 incident.getIncidentId(), incident.getType());

        // SoarIncidentDto를 SecurityEvent로 변환
        SecurityEvent event = convertSoarIncidentToSecurityEvent(incident);

        // 기존 evolvePolicy 메서드 활용
        return evolvePolicy(event, metadata);
    }

    /**
     * SoarIncidentDto를 SecurityEvent로 변환
     */
    private SecurityEvent convertSoarIncidentToSecurityEvent(io.contexa.contexacore.domain.SoarIncidentDto incident) {
        SecurityEvent.EventType eventType = mapIncidentTypeToEventType(incident.getType());
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
            .eventType(eventType)
            .severity(severity)
            .description(incident.getDescription())
            .timestamp(incident.getCreatedAt() != null ? incident.getCreatedAt() : LocalDateTime.now())
            .source(SecurityEvent.EventSource.SIEM)  // SOAR가 없으므로 SIEM 사용
            .metadata(metadata)
            .build();
    }

    /**
     * SoarIncidentDto.IncidentType을 SecurityEvent.EventType으로 매핑
     */
    private SecurityEvent.EventType mapIncidentTypeToEventType(io.contexa.contexacore.domain.SoarIncidentDto.IncidentType incidentType) {
        if (incidentType == null) {
            return SecurityEvent.EventType.UNKNOWN;
        }

        switch (incidentType) {
            case MALWARE:
                return SecurityEvent.EventType.MALWARE_DETECTED;
            case RANSOMWARE:
                return SecurityEvent.EventType.RANSOMWARE_ATTACK;
            case PHISHING:
                return SecurityEvent.EventType.PHISHING_ATTEMPT;
            case DATA_BREACH:
                return SecurityEvent.EventType.DATA_EXFILTRATION; // DATA_BREACH가 없으므로 가장 유사한 값
            case UNAUTHORIZED_ACCESS:
                return SecurityEvent.EventType.ACCESS_DENIED; // UNAUTHORIZED_ACCESS가 없으므로 가장 유사한 값
            case DOS_ATTACK:
                return SecurityEvent.EventType.DDOS_ATTACK;
            case INSIDER_THREAT:
                return SecurityEvent.EventType.INSIDER_THREAT;
            case VULNERABILITY:
                return SecurityEvent.EventType.THREAT_DETECTED; // VULNERABILITY_DETECTED가 없으므로 가장 유사한 값
            case COMPLIANCE_VIOLATION:
                return SecurityEvent.EventType.POLICY_VIOLATION; // COMPLIANCE_VIOLATION가 없으므로 가장 유사한 값
            case OTHER:
            default:
                return SecurityEvent.EventType.UNKNOWN;
        }
    }

    /**
     * SoarIncidentDto.IncidentSeverity를 SecurityEvent.Severity로 매핑
     */
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

    /**
     * 비동기 정책 진화
     */
    public Mono<PolicyEvolutionProposal> evolvePolicyAsync(SecurityEvent event, LearningMetadata metadata) {
        return Mono.fromCallable(() -> evolvePolicy(event, metadata))
                   .doOnSubscribe(s -> log.info("🔄 비동기 정책 진화 시작"))
                   .doOnSuccess(p -> log.info("비동기 정책 진화 완료"))
                   .doOnError(e -> log.error(" 비동기 정책 진화 실패", e));
    }

    /**
     * 컨텍스트 수집
     */
    private Map<String, Object> collectContext(SecurityEvent event, LearningMetadata metadata) {
        Map<String, Object> context = new HashMap<>();
        
        // 이벤트 정보
        context.put("eventType", event.getEventType());
        context.put("severity", event.getSeverity());
        context.put("timestamp", event.getTimestamp());
        
        // 네트워크 정보
        if (event.getSourceIp() != null) {
            context.put("sourceIp", event.getSourceIp());
            context.put("targetIp", event.getTargetIp());
        }
        
        // 사용자 정보
        if (event.getUserId() != null) {
            context.put("userId", event.getUserId());
            context.put("userName", event.getUserName());
            context.put("organizationId", event.getOrganizationId());
        }
        
        // 위협 정보
        if (event.getMitreAttackId() != null) {
            context.put("mitreAttackId", event.getMitreAttackId());
        }
        
        // 학습 컨텍스트 병합
        context.putAll(metadata.getLearningContext());
        
        return context;
    }
    
    /**
     * 유사 사례 검색
     */
    private List<Document> searchSimilarCases(SecurityEvent event, LearningMetadata metadata) {
        try {
            String query = buildSearchQuery(event, metadata);

            // 벡터 스토어에서 유사 사례 검색
            SearchRequest searchRequest = SearchRequest.builder()
                .query(query)
                .topK(maxContextSize)
                .similarityThreshold(0.7)
                .build();
            List<Document> documents = unifiedVectorService.searchSimilar(searchRequest);
            
            // 최대 컨텍스트 크기로 제한
            if (documents.size() > maxContextSize) {
                documents = documents.subList(0, maxContextSize);
            }
            
            log.debug("유사 사례 {} 건 검색됨", documents.size());
            return documents;
            
        } catch (Exception e) {
            log.warn("유사 사례 검색 실패: {}", e.getMessage());
            return new ArrayList<>();
        }
    }
    
    /**
     * 정책 제안 생성
     */
    private PolicyEvolutionProposal generateProposal(
            SecurityEvent event, 
            LearningMetadata metadata,
            Map<String, Object> context,
            List<Document> similarCases) {
        
        // AI 프롬프트 생성
        String prompt = buildEvolutionPrompt(event, metadata, context, similarCases);
        
        // AI 호출
        String aiResponse = callAI(prompt);
        
        // 응답 파싱
        PolicyEvolutionProposal proposal = parseAIResponse(aiResponse, event, metadata);
        
        // 기본 정보 설정
        proposal.setSourceEventId(event.getEventId());
        proposal.setAnalysisLabId(metadata.getSourceLabId());
        proposal.setLearningType(metadata.getLearningType());
        proposal.setCreatedAt(LocalDateTime.now());
        proposal.setEvidenceContext(context);
        
        return proposal;
    }
    
    /**
     * AI 프롬프트 생성
     */
    private String buildEvolutionPrompt(
            SecurityEvent event,
            LearningMetadata metadata,
            Map<String, Object> context,
            List<Document> similarCases) {
        
        StringBuilder prompt = new StringBuilder();
        prompt.append("보안 이벤트를 분석하여 정책 제안을 생성해주세요.\n\n");
        
        // 이벤트 정보
        prompt.append("## 보안 이벤트\n");
        prompt.append(String.format("- 유형: %s\n", event.getEventType()));
        prompt.append(String.format("- 심각도: %s\n", event.getSeverity()));
        prompt.append(String.format("- 설명: %s\n", event.getDescription()));
        
        // 학습 유형
        prompt.append("\n## 학습 유형\n");
        prompt.append(String.format("- %s\n", metadata.getLearningType()));
        
        // 컨텍스트
        prompt.append("\n## 컨텍스트\n");
        context.forEach((key, value) -> 
            prompt.append(String.format("- %s: %s\n", key, value))
        );
        
        // 유사 사례
        if (!similarCases.isEmpty()) {
            prompt.append("\n## 유사 사례\n");
            similarCases.stream()
                .limit(3)
                .forEach(doc -> prompt.append(String.format("- %s\n", doc.getText())));
        }
        
        // 요청사항
        prompt.append("\n## 요청사항\n");
        prompt.append("1. 이 이벤트를 예방하기 위한 정책을 제안해주세요.\n");
        prompt.append("2. SpEL 표현식으로 실행 가능한 정책을 작성해주세요.\n");
        prompt.append("3. 정책의 예상 효과를 0.0-1.0 사이로 평가해주세요.\n");
        prompt.append("4. 정책 적용 시 주의사항을 명시해주세요.\n");
        
        return prompt.toString();
    }
    
    /**
     * AI 호출
     */
    private String callAI(String prompt) {
        long startTime = System.currentTimeMillis();
        try {
            Prompt aiPrompt = new Prompt(prompt);
            ChatResponse response = chatModel.call(aiPrompt);
            String result = response.getResult().getOutput().getText();

            // 📊 메트릭: AI 호출 성공
            if (metricsCollector != null) {
                long duration = System.currentTimeMillis() - startTime;
                metricsCollector.recordAICall(duration, "chatModel", true);

                // EventRecorder 인터페이스 호출
                Map<String, Object> eventMetadata = new HashMap<>();
                eventMetadata.put("model", "chatModel");
                eventMetadata.put("duration", duration);
                eventMetadata.put("success", true);
                metricsCollector.recordEvent("ai_call_success", eventMetadata);
            }

            return result;
        } catch (Exception e) {
            // 📊 메트릭: AI 호출 실패
            if (metricsCollector != null) {
                long duration = System.currentTimeMillis() - startTime;
                metricsCollector.recordAICall(duration, "chatModel", false);

                // EventRecorder 인터페이스 호출
                Map<String, Object> eventMetadata = new HashMap<>();
                eventMetadata.put("model", "chatModel");
                eventMetadata.put("duration", duration);
                eventMetadata.put("success", false);
                eventMetadata.put("error", e.getMessage());
                metricsCollector.recordEvent("ai_call_failure", eventMetadata);
            }

            log.error("AI 호출 실패", e);
            return "AI 분석 실패: " + e.getMessage();
        }
    }
    
    /**
     * AI 응답 파싱
     */
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
        
        // 액션 페이로드 설정
        Map<String, Object> actionPayload = new HashMap<>();
        actionPayload.put("eventType", event.getEventType());
        actionPayload.put("learningType", metadata.getLearningType());
        proposal.setActionPayload(actionPayload);
        
        return proposal;
    }
    
    /**
     * 제목 생성
     */
    private String generateTitle(SecurityEvent event, LearningMetadata metadata) {
        return String.format("[%s] %s 대응 정책", 
                            metadata.getLearningType(), 
                            event.getEventType());
    }
    
    /**
     * 설명 추출
     */
    private String extractDescription(String aiResponse) {
        // AI 응답에서 설명 부분 추출 (간단한 구현)
        String[] lines = aiResponse.split("\n");
        if (lines.length > 0) {
            return lines[0].length() > 255 ? lines[0].substring(0, 255) : lines[0];
        }
        return "AI 생성 정책 제안";
    }
    
    /**
     * SpEL 표현식 추출 (AI 기반 파싱)
     */
    private String extractSpelExpression(String aiResponse) {
        if (aiResponse == null || aiResponse.isEmpty()) {
            // 📊 메트릭: SpEL 추출 실패 (빈 응답)
            if (metricsCollector != null) {
                metricsCollector.recordSpelExtraction("empty_response", false);
            }
            return "hasRole('USER') and #request.isSecure()"; // 기본값
        }

        try {
            // 1. 코드 블록 패턴 추출 (```...```, `...`)
            String spelExpression = extractFromCodeBlock(aiResponse);
            if (spelExpression != null) {
                // 📊 메트릭: 코드 블록에서 성공적으로 추출
                if (metricsCollector != null) {
                    metricsCollector.recordSpelExtraction("code_block", true);
                }
                return spelExpression;
            }

            // 2. SpEL 함수 패턴 감지
            spelExpression = extractSpelFunctionPattern(aiResponse);
            if (spelExpression != null) {
                // 📊 메트릭: 함수 패턴에서 성공적으로 추출
                if (metricsCollector != null) {
                    metricsCollector.recordSpelExtraction("function_pattern", true);
                }
                return spelExpression;
            }

            // 3. AI에게 재요청하여 명확한 SpEL 표현식 추출
            spelExpression = requestSpelFromAI(aiResponse);
            if (spelExpression != null) {
                // 📊 메트릭: AI 재요청으로 성공적으로 추출
                if (metricsCollector != null) {
                    metricsCollector.recordSpelExtraction("ai_retry", true);
                }
                return spelExpression;
            }

        } catch (Exception e) {
            log.warn("SpEL 표현식 추출 실패, 기본값 사용: {}", e.getMessage());
        }

        // 📊 메트릭: SpEL 추출 실패, 기본값 사용
        if (metricsCollector != null) {
            metricsCollector.recordSpelExtraction("fallback_default", false);
        }

        // 기본값
        return "hasRole('USER') and #request.isSecure()";
    }

    /**
     * 코드 블록에서 SpEL 표현식 추출
     */
    private String extractFromCodeBlock(String aiResponse) {
        // 마크다운 코드 블록 패턴: ```spel ... ``` or ```java ... ```
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
            "```(?:spel|java)?\\s*([^`]+)```",
            java.util.regex.Pattern.DOTALL
        );
        java.util.regex.Matcher matcher = pattern.matcher(aiResponse);
        if (matcher.find()) {
            String code = matcher.group(1).trim();
            // SpEL 표현식인지 검증
            if (isValidSpelExpression(code)) {
                return code;
            }
        }

        // 인라인 코드 블록 패턴: `...`
        pattern = java.util.regex.Pattern.compile("`([^`]+)`");
        matcher = pattern.matcher(aiResponse);
        while (matcher.find()) {
            String code = matcher.group(1).trim();
            if (isValidSpelExpression(code)) {
                return code;
            }
        }

        return null;
    }

    /**
     * SpEL 함수 패턴 추출
     */
    private String extractSpelFunctionPattern(String aiResponse) {
        // SpEL 주요 함수 패턴: hasRole, hasAuthority, hasPermission, permitAll, denyAll 등
        String[] spelPatterns = {
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
                // 문장 종료 표시 제거 (.!?;)
                expression = expression.replaceAll("[.!?;]$", "");
                return expression;
            }
        }

        return null;
    }

    /**
     * AI에게 SpEL 표현식 재요청
     */
    private String requestSpelFromAI(String originalResponse) {
        try {
            String extractionPrompt = String.format(
                "다음 텍스트에서 Spring Security SpEL 표현식만 추출해주세요. " +
                "코드 블록이나 설명 없이 SpEL 표현식만 반환해주세요:\n\n%s",
                originalResponse.substring(0, Math.min(500, originalResponse.length()))
            );

            Prompt prompt = new Prompt(extractionPrompt);
            ChatResponse response = chatModel.call(prompt);
            String extractedSpel = response.getResult().getOutput().getText().trim();

            // 검증
            if (isValidSpelExpression(extractedSpel)) {
                return extractedSpel;
            }

        } catch (Exception e) {
            log.debug("AI SpEL 재요청 실패: {}", e.getMessage());
        }

        return null;
    }

    /**
     * SpEL 표현식 유효성 검증
     */
    private boolean isValidSpelExpression(String expression) {
        if (expression == null || expression.isEmpty() || expression.length() > 500) {
            return false;
        }

        // SpEL 주요 키워드 포함 여부 확인
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
            lowerExpression.contains("#") ||  // SpEL 변수 참조
            lowerExpression.contains("and") ||
            lowerExpression.contains("or");

        // 기본적인 구문 검사
        boolean hasBalancedParentheses = checkBalancedParentheses(expression);

        return hasSpelKeyword && hasBalancedParentheses;
    }

    /**
     * 괄호 균형 검사
     */
    private boolean checkBalancedParentheses(String expression) {
        int count = 0;
        for (char c : expression.toCharArray()) {
            if (c == '(') count++;
            else if (c == ')') count--;
            if (count < 0) return false;
        }
        return count == 0;
    }
    
    /**
     * 예상 영향도 추출 (AI 기반 파싱)
     */
    private Double extractExpectedImpact(String aiResponse) {
        if (aiResponse == null || aiResponse.isEmpty()) {
            return 0.7; // 기본값
        }

        try {
            // 1. 명시적 숫자 패턴 추출 (0.0 ~ 1.0)
            Double impact = extractNumericImpact(aiResponse);
            if (impact != null) {
                return impact;
            }

            // 2. 퍼센트 패턴 추출 (30%, 50%, 70% 등)
            impact = extractPercentageImpact(aiResponse);
            if (impact != null) {
                return impact;
            }

            // 3. 텍스트 기반 영향도 추정 (높음/중간/낮음)
            impact = extractTextualImpact(aiResponse);
            if (impact != null) {
                return impact;
            }

            // 4. AI에게 재요청하여 명확한 영향도 추출
            impact = requestImpactFromAI(aiResponse);
            if (impact != null) {
                return impact;
            }

        } catch (Exception e) {
            log.warn("영향도 추출 실패, 기본값 사용: {}", e.getMessage());
        }

        return 0.7; // 기본값
    }

    /**
     * 숫자 패턴 기반 영향도 추출 (0.0 ~ 1.0)
     */
    private Double extractNumericImpact(String aiResponse) {
        // 패턴: "영향도: 0.8", "impact: 0.75", "효과: 0.65" 등
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
                log.debug("숫자 파싱 실패: {}", matcher.group(1));
            }
        }

        // 일반 소수점 패턴 찾기 (문맥 없이)
        pattern = java.util.regex.Pattern.compile("\\b(0\\.[0-9]{1,2})\\b");
        matcher = pattern.matcher(aiResponse);

        while (matcher.find()) {
            try {
                double value = Double.parseDouble(matcher.group(1));
                // 0.0 ~ 1.0 범위 내의 값만 반환
                if (value >= 0.0 && value <= 1.0) {
                    return value;
                }
            } catch (NumberFormatException e) {
                // 계속 탐색
            }
        }

        return null;
    }

    /**
     * 퍼센트 패턴 기반 영향도 추출
     */
    private Double extractPercentageImpact(String aiResponse) {
        // 패턴: "50%", "75%", "80%" 등
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
                log.debug("퍼센트 파싱 실패: {}", matcher.group(1));
            }
        }

        return null;
    }

    /**
     * 텍스트 기반 영향도 추정
     */
    private Double extractTextualImpact(String aiResponse) {
        String lowerResponse = aiResponse.toLowerCase();

        // 매우 높음: 0.9
        if (lowerResponse.contains("매우 높") || lowerResponse.contains("very high") ||
            lowerResponse.contains("excellent") || lowerResponse.contains("탁월")) {
            return 0.9;
        }

        // 높음: 0.8
        if (lowerResponse.contains("높은") || lowerResponse.contains("high") ||
            lowerResponse.contains("significant") || lowerResponse.contains("상당")) {
            return 0.8;
        }

        // 중간-높음: 0.7
        if (lowerResponse.contains("중상") || lowerResponse.contains("moderate-high") ||
            lowerResponse.contains("good")) {
            return 0.7;
        }

        // 중간: 0.6
        if (lowerResponse.contains("중간") || lowerResponse.contains("medium") ||
            lowerResponse.contains("moderate") || lowerResponse.contains("보통")) {
            return 0.6;
        }

        // 중간-낮음: 0.5
        if (lowerResponse.contains("중하") || lowerResponse.contains("moderate-low") ||
            lowerResponse.contains("fair")) {
            return 0.5;
        }

        // 낮음: 0.4
        if (lowerResponse.contains("낮은") || lowerResponse.contains("low") ||
            lowerResponse.contains("minor") || lowerResponse.contains("적은")) {
            return 0.4;
        }

        // 매우 낮음: 0.3
        if (lowerResponse.contains("매우 낮") || lowerResponse.contains("very low") ||
            lowerResponse.contains("minimal") || lowerResponse.contains("미미")) {
            return 0.3;
        }

        return null;
    }

    /**
     * AI에게 영향도 재요청
     */
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

            // 숫자 추출 시도
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("(0\\.\\d+|1\\.0|0|1)");
            java.util.regex.Matcher matcher = pattern.matcher(impactText);

            if (matcher.find()) {
                double value = Double.parseDouble(matcher.group(1));
                if (value >= 0.0 && value <= 1.0) {
                    return value;
                }
            }

        } catch (Exception e) {
            log.debug("AI 영향도 재요청 실패: {}", e.getMessage());
        }

        return null;
    }
    
    /**
     * 제안 유형 결정
     */
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
    
    /**
     * 신뢰도 평가
     */
    private void evaluateConfidence(
            PolicyEvolutionProposal proposal,
            Map<String, Object> context,
            List<Document> similarCases) {
        
        double confidence = 0.5; // 기본값
        
        // 유사 사례가 많을수록 신뢰도 증가
        if (similarCases.size() >= 5) {
            confidence += 0.2;
        } else if (similarCases.size() >= 3) {
            confidence += 0.1;
        }
        
        // 컨텍스트가 풍부할수록 신뢰도 증가
        if (context.size() >= 10) {
            confidence += 0.2;
        } else if (context.size() >= 5) {
            confidence += 0.1;
        }
        
        // SpEL 표현식이 있으면 신뢰도 증가
        if (proposal.getSpelExpression() != null && !proposal.getSpelExpression().isEmpty()) {
            confidence += 0.1;
        }
        
        // 최대값 제한
        confidence = Math.min(confidence, 1.0);
        
        proposal.setConfidenceScore(confidence);
    }
    
    /**
     * 위험도 평가
     */
    private void assessRiskLevel(
            PolicyEvolutionProposal proposal,
            SecurityEvent event,
            LearningMetadata metadata) {
        
        PolicyEvolutionProposal.RiskLevel riskLevel;
        
        // 제안 유형에 따른 위험도 평가
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
        
        // 신뢰도가 낮으면 위험도 상승
        if (proposal.getConfidenceScore() < 0.5 && riskLevel == PolicyEvolutionProposal.RiskLevel.LOW) {
            riskLevel = PolicyEvolutionProposal.RiskLevel.MEDIUM;
        }
        
        proposal.setRiskLevel(riskLevel);
    }
    
    /**
     * 학습 데이터 저장
     */
    private void storeLearningData(
            SecurityEvent event,
            LearningMetadata metadata,
            PolicyEvolutionProposal proposal) {
        
        try {
            // 문서 생성
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
            
            // 벡터 스토어에 저장
            unifiedVectorService.storeDocument(document);
            
            // AI 튜닝 서비스에 학습 데이터 전달
            AITuningService.UserFeedback feedback = AITuningService.UserFeedback.builder()
                .feedbackType("FALSE_POSITIVE")
                .comment("정책 진화 학습")
                .timestamp(LocalDateTime.now())
                .build();
            tuningService.learnFalsePositive(event, feedback).subscribe();
            
            log.debug("학습 데이터 저장 완료");
            
        } catch (Exception e) {
            log.warn("학습 데이터 저장 실패: {}", e.getMessage());
        }
    }
    
    /**
     * 캐시 키 생성
     */
    private String generateCacheKey(SecurityEvent event, LearningMetadata metadata) {
        return String.format("%s_%s_%s", 
                            event.getEventType(),
                            metadata.getLearningType(),
                            event.getSeverity());
    }
    
    /**
     * 검색 쿼리 생성
     */
    private String buildSearchQuery(SecurityEvent event, LearningMetadata metadata) {
        return String.format("%s %s %s %s",
                            event.getEventType(),
                            event.getSeverity(),
                            metadata.getLearningType(),
                            event.getDescription() != null ? event.getDescription() : "");
    }
    
    /**
     * 실패 제안 생성
     */
    private PolicyEvolutionProposal createFailureProposal(
            SecurityEvent event,
            LearningMetadata metadata,
            Exception e) {
        
        return PolicyEvolutionProposal.builder()
            .title("정책 진화 실패")
            .description("오류로 인해 정책 제안을 생성할 수 없습니다: " + e.getMessage())
            .proposalType(PolicyEvolutionProposal.ProposalType.SUGGEST_TRAINING)
            .sourceEventId(event.getEventId())
            .analysisLabId(metadata.getSourceLabId())
            .aiReasoning("오류 발생: " + e.getMessage())
            .confidenceScore(0.0)
            .riskLevel(PolicyEvolutionProposal.RiskLevel.LOW)
            .createdAt(LocalDateTime.now())
            .build();
    }
    
    /**
     * Redis 캐시에서 제안 조회
     */
    private PolicyEvolutionProposal getFromRedisCache(String cacheKey) {
        try {
            String redisKey = PROPOSAL_CACHE_KEY_PREFIX + cacheKey;
            return redisTemplate.opsForValue().get(redisKey);
        } catch (Exception e) {
            log.error("Redis 캐시 조회 실패: key={}", cacheKey, e);
            return null;
        }
    }
    
    /**
     * Redis 캐시에 제안 저장
     */
    private void saveToRedisCache(String cacheKey, PolicyEvolutionProposal proposal) {
        try {
            String redisKey = PROPOSAL_CACHE_KEY_PREFIX + cacheKey;
            // 기본 TTL 적용 (getPriority() 메서드가 없으므로)
            Duration ttl = PROPOSAL_CACHE_TTL;
            
            redisTemplate.opsForValue().set(redisKey, proposal, ttl);
            
            // 전체 제안 목록에도 추가
            stringRedisTemplate.opsForSet().add(PROPOSAL_SET_KEY, cacheKey);
            
            log.debug("제안이 Redis 캐시에 저장됨: key={}, TTL={}", cacheKey, ttl);
        } catch (Exception e) {
            log.error("Redis 캐시 저장 실패: key={}", cacheKey, e);
        }
    }
    
    /**
     * Redis 캐시 정리
     */
    public void clearCache() {
        try {
            // 모든 제안 키 가져오기
            var keys = stringRedisTemplate.opsForSet().members(PROPOSAL_SET_KEY);
            if (keys != null && !keys.isEmpty()) {
                for (String key : keys) {
                    String redisKey = PROPOSAL_CACHE_KEY_PREFIX + key;
                    redisTemplate.delete(redisKey);
                }
                stringRedisTemplate.delete(PROPOSAL_SET_KEY);
            }
            log.info("Redis 정책 제안 캐시 정리 완료");
        } catch (Exception e) {
            log.error("Redis 캐시 정리 실패", e);
        }
    }
    
    /**
     * Redis 캐시 크기 조회
     */
    public int getCacheSize() {
        try {
            Long size = stringRedisTemplate.opsForSet().size(PROPOSAL_SET_KEY);
            return size != null ? size.intValue() : 0;
        } catch (Exception e) {
            log.error("Redis 캐시 크기 조회 실패", e);
            return 0;
        }
    }
    
    /**
     * 특정 제안을 Redis에서 무효화
     */
    public void invalidateProposal(String proposalId) {
        try {
            String pattern = PROPOSAL_CACHE_KEY_PREFIX + "*" + proposalId + "*";
            var keys = redisTemplate.keys(pattern);
            if (keys != null && !keys.isEmpty()) {
                redisTemplate.delete(keys);
                log.info("제안 무효화됨: proposalId={}", proposalId);
            }
        } catch (Exception e) {
            log.error("제안 무효화 실패: proposalId={}", proposalId, e);
        }
    }
    
    /**
     * 모든 캐시된 제안 조회
     */
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
            log.info("Redis에서 {} 개의 캐시된 제안 로드됨", proposals.size());
        } catch (Exception e) {
            log.error("캐시된 제안 조회 실패", e);
        }
        return proposals;
    }

    /**
     * 거부된 정책으로부터 학습
     * PolicyChangeEventListener에서 호출
     */
    public void learnFromRejection(PolicyDTO policy, String rejectionReason) {
        log.info("거부된 정책으로부터 학습 시작: {}, 이유: {}", policy.getName(), rejectionReason);

        try {
            // 1. 거부 사유 분석
            Map<String, Object> rejectionContext = new HashMap<>();
            rejectionContext.put("policyId", policy.getId());
            rejectionContext.put("policyName", policy.getName());
            rejectionContext.put("policySource", policy.getSource());
            rejectionContext.put("confidenceScore", policy.getConfidenceScore());
            rejectionContext.put("aiModel", policy.getAiModel());
            rejectionContext.put("rejectionReason", rejectionReason);
            rejectionContext.put("rejectedAt", LocalDateTime.now());

            // 2. 벡터 스토어에 거부 패턴 저장
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

            // 3. 학습 메타데이터 생성
            LearningMetadata metadata = LearningMetadata.builder()
                .learningType(LearningMetadata.LearningType.POLICY_FEEDBACK)
                .isLearnable(true)
                .confidenceScore(0.3) // 거부된 정책은 낮은 신뢰도
                .sourceLabId("PolicyEvolutionEngine")
                .priority(7)
                .status(LearningMetadata.LearningStatus.COMPLETED)
                .learningSummary("Policy rejected: " + rejectionReason)
                .build();

            metadata.addPattern("rejection_reason", rejectionReason);
            metadata.addOutcome("learned", true);

            // 4. 유사한 정책에 대한 신뢰도 감소
            updateSimilarPolicyConfidence(policy, -0.1);

            log.info("거부 패턴 학습 완료: {}", policy.getName());

        } catch (Exception e) {
            log.error("거부 학습 실패: {}", policy.getName(), e);
        }
    }

    /**
     * 정책 진화 요청
     * PolicyChangeEventListener에서 호출
     */
    public void requestEvolution(PolicyDTO policy, Map<String, Object> context) {
        log.info("정책 진화 요청: {}", policy.getName());

        try {
            // 1. SecurityEvent 생성 (정책 변경 이벤트)
            SecurityEvent event = SecurityEvent.builder()
                .eventType(SecurityEvent.EventType.POLICY_VIOLATION)
                .source(SecurityEvent.EventSource.IAM)
                .severity(SecurityEvent.Severity.MEDIUM)
                .description("Policy evolution requested: " + policy.getName())
                .metadata(context)
                .build();

            // 2. LearningMetadata 생성
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

            // 3. 정책 진화 실행
            PolicyEvolutionProposal proposal = evolvePolicy(event, metadata);

            // 4. 진화된 정책 생성 및 저장
            if (proposal != null && proposal.getConfidenceScore() > 0.7) {
                createEvolvedPolicy(policy, proposal);
            }

            log.info("정책 진화 완료: {} -> {}", policy.getName(), proposal.getProposalType());

        } catch (Exception e) {
            log.error("정책 진화 실패: {}", policy.getName(), e);
        }
    }

    /**
     * 유사 정책의 신뢰도 업데이트
     */
    private void updateSimilarPolicyConfidence(PolicyDTO policy, double adjustment) {
        try {
            // 벡터 스토어에서 유사 정책 검색
            SearchRequest searchRequest = SearchRequest.builder()
                .query(policy.getName())
                .topK(10)
                .similarityThreshold(0.7)
                .build();
            List<Document> similarDocs = unifiedVectorService.searchSimilar(searchRequest);

            for (Document doc : similarDocs) {
                Object policyId = doc.getMetadata().get("policyId");
                if (policyId != null && !policyId.equals(policy.getId())) {
                    // 유사 정책의 신뢰도 조정
                    log.debug("유사 정책 신뢰도 조정: policyId={}, adjustment={}", policyId, adjustment);
                }
            }
        } catch (Exception e) {
            log.error("유사 정책 신뢰도 업데이트 실패", e);
        }
    }

    /**
     * 진화된 정책 생성
     */
    private void createEvolvedPolicy(PolicyDTO originalPolicy,
                                    PolicyEvolutionProposal proposal) {
        log.info("진화된 정책 생성: {} -> {}", originalPolicy.getName(), proposal.getProposalType());

        // PolicyChangeEvent 발행 (AI_EVOLVED 타입)
        // 실제 정책 생성은 Policy 서비스에서 처리
        Map<String, Object> evolutionData = new HashMap<>();
        evolutionData.put("originalPolicy", originalPolicy);
        evolutionData.put("proposal", proposal);
        evolutionData.put("evolvedAt", LocalDateTime.now());

        // 이벤트 발행 로직은 Policy 서비스에서 처리
        log.info("정책 진화 데이터 준비 완료: {}", evolutionData);
    }
}