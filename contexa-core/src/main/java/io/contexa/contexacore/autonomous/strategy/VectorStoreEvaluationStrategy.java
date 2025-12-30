package io.contexa.contexacore.autonomous.strategy;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityContext;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Vector Store 기반 위협 평가 전략 - AI Native
 *
 * UnifiedVectorService를 활용하여 과거 패턴과의 유사도 검색을 수행하고,
 * 검색 결과를 LLM에 전달하여 위협을 평가합니다.
 *
 * AI Native 원칙:
 * - similarityThreshold 비활성화 (LLM이 관련성 판단)
 * - 규칙 기반 점수 계산 제거 (riskScore, confidence는 LLM이 결정)
 * - ThreatLevel 임계값 매핑 제거 (LLM이 직접 결정)
 * - 플랫폼은 검색 결과만 제공, 평가는 LLM이 담당
 */
@Slf4j
@RequiredArgsConstructor
public class VectorStoreEvaluationStrategy implements ThreatEvaluationStrategy {

    @Autowired(required = false)
    private UnifiedVectorService unifiedVectorService;
    
    private static final String STRATEGY_NAME = "VECTOR_STORE";
    // AI Native: similarityThreshold 비활성화 (LLM이 관련성 판단)
    private static final double DEFAULT_SIMILARITY_THRESHOLD = 0.0;
    private static final int DEFAULT_TOP_K = 10;
    
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        try {
            log.debug("[VectorStoreEvaluationStrategy][AI Native] Vector Store threat evaluation for event: {}", event.getEventId());

            if (unifiedVectorService == null) {
                log.warn("[VectorStoreEvaluationStrategy][AI Native] UnifiedVectorService not available");
                return createFallbackAssessment(event);
            }

            // 1. 이벤트를 쿼리 텍스트로 변환
            String queryText = buildQueryFromEvent(event);

            // 2. Vector Store에서 유사 패턴 검색 (AI Native: threshold 비활성화)
            List<Document> similarPatterns = searchSimilarPatterns(queryText);

            // 3. 위협 지표 추출 (검색 결과 기반, 규칙 기반 아님)
            List<ThreatIndicator> indicators = extractIndicatorsFromPatterns(similarPatterns, event);

            // AI Native: riskScore, confidence, ThreatLevel은 LLM이 결정해야 함
            // 플랫폼은 검색 결과만 제공

            return ThreatAssessment.builder()
                .eventId(event.getEventId())
                .assessmentId(UUID.randomUUID().toString())
                .assessedAt(LocalDateTime.now())
                .evaluator(getStrategyName())
                .riskScore(Double.NaN)  // AI Native: LLM이 결정해야 함
                .indicators(convertToStringList(indicators))
                .recommendedActions(List.of("LLM_ANALYSIS_REQUIRED"))  // AI Native: LLM 분석 필요
                .confidence(Double.NaN)  // AI Native: LLM이 결정해야 함
                // AI Native v3.1: metadata 필드 제거됨 - 죽은 필드
                .action("ESCALATE")  // AI Native: LLM 분석 필요
                .build();

        } catch (Exception e) {
            log.error("[VectorStoreEvaluationStrategy][AI Native] Error for event: {}", event.getEventId(), e);
            return createErrorAssessment(event, e);
        }
    }
    
    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        log.debug("[VectorStoreEvaluationStrategy][AI Native] Context-aware evaluation for event: {}", event.getEventId());

        // AI Native: 컨텍스트 기반 조정도 LLM이 담당
        // 플랫폼은 컨텍스트 정보를 LLM에 전달만 함
        return evaluate(event);
    }
    
    @Override
    public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        try {
            if (event == null) {
                log.warn("SecurityEvent가 null입니다. 지표 추출을 건너뜁니다.");
                return new ArrayList<>();
            }
            
            if (unifiedVectorService == null) {
                log.warn("UnifiedVectorService가 null입니다. 지표 추출을 건너뜁니다.");
                return new ArrayList<>();
            }
            
            String queryText = buildQueryFromEvent(event);
            List<Document> patterns = searchSimilarPatterns(queryText);
            return extractIndicatorsFromPatterns(patterns, event);
            
        } catch (Exception e) {
            log.error("지표 추출 중 오류 발생", e);
            return new ArrayList<>();
        }
    }
    
    @Override
    public String getStrategyName() {
        return STRATEGY_NAME;
    }
    
    @Override
    public String getDescription() {
        return "Vector Store pattern-based threat evaluation using machine learning similarity search";
    }
    
    // @Override 제거: ThreatEvaluationStrategy 인터페이스에서 mapToFramework 메서드 삭제됨
    public Map<String, String> mapToFramework(SecurityEvent event) {
        Map<String, String> mapping = new HashMap<>();
        mapping.put("FRAMEWORK", "VECTOR_PATTERN_MATCHING");
        mapping.put("METHOD", "SIMILARITY_SEARCH");
        // AI Native v4.0.0: eventType 제거 - severity 기반
        mapping.put("SEVERITY", event.getSeverity() != null ? event.getSeverity().toString() : "INFO");
        mapping.put("ALGORITHM", "COSINE_SIMILARITY");
        return mapping;
    }
    
    /**
     * AI Native: LLM이 직접 recommendedActions 결정
     * 규칙 기반 액션 추천 제거
     */
    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        // AI Native: 규칙 기반 액션 추천 제거
        // LLM이 ThreatAssessment.recommendedActions를 직접 결정
        return List.of("LLM_ANALYSIS_REQUIRED");
    }
    
    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        // AI Native: LLM이 riskScore를 직접 결정해야 함
        // 규칙 기반 가중치 적용 로직 제거
        return Double.NaN;
    }
    
    // AI Native v4.0.0: EventType 기반 canEvaluate 제거 - Severity 기반으로 전환
    @Override
    public boolean canEvaluate(SecurityEvent.Severity severity) {
        // Vector Store는 모든 심각도의 이벤트를 패턴 매칭으로 처리 가능
        return unifiedVectorService != null;
    }
    
    @Override
    public int getPriority() {
        return 80; // 중간 우선순위 (기본보다 높음)
    }
    
    // === Private Helper Methods ===
    
    private String buildQueryFromEvent(SecurityEvent event) {
        StringBuilder query = new StringBuilder();
        
        // AI Native v4.0.0: eventType 제거 - severity 및 source 기반
        query.append("severity:").append(event.getSeverity() != null ? event.getSeverity() : "INFO");
        
        if (event.getSourceIp() != null) {
            query.append(" source_ip:").append(event.getSourceIp());
        }
        
        // AI Native v4.0.0: targetResource 필드 제거 - metadata에서 조회
        Object targetResource = event.getMetadata() != null ? event.getMetadata().get("targetResource") : null;
        if (targetResource != null) {
            query.append(" target:").append(targetResource);
        }
        
        if (event.getSeverity() != null) {
            query.append(" severity:").append(event.getSeverity());
        }
        
        if (event.getUserId() != null) {
            query.append(" user:").append(event.getUserId());
        }
        
        return query.toString();
    }
    
    private String buildContextQuery(SecurityEvent event, SecurityContext context) {
        StringBuilder query = new StringBuilder();
        query.append(buildQueryFromEvent(event));

        if (context.getUserId() != null) {
            query.append(" context_user:").append(context.getUserId());
        }

        // AI Native: trustScore 임계값 기반 분류 제거
        // trustScore를 그대로 쿼리에 포함하여 LLM이 판단하도록 함
        if (context.getTrustScore() != null) {
            query.append(" trust_score:").append(context.getTrustScore());
        }

        return query.toString();
    }
    
    private List<Document> searchSimilarPatterns(String query) {
        try {
            SearchRequest searchRequest = SearchRequest.builder()
                .query(query)
                .topK(DEFAULT_TOP_K)
                .similarityThreshold(DEFAULT_SIMILARITY_THRESHOLD)
                .build();
                
            return unifiedVectorService.searchSimilar(searchRequest);
        } catch (Exception e) {
            log.error("Error searching similar patterns", e);
            return new ArrayList<>();
        }
    }
    
    private List<Document> searchContextPatterns(String contextQuery) {
        try {
            SearchRequest searchRequest = SearchRequest.builder()
                .query(contextQuery)
                .topK(5)
                // AI Native: similarityThreshold 비활성화 (LLM이 관련성 판단)
                .similarityThreshold(0.0)
                .build();

            return unifiedVectorService.searchSimilar(searchRequest);
        } catch (Exception e) {
            log.error("[VectorStoreEvaluationStrategy][AI Native] Error searching context patterns", e);
            return new ArrayList<>();
        }
    }
    
    private List<ThreatIndicator> extractIndicatorsFromPatterns(List<Document> patterns, SecurityEvent event) {
        List<ThreatIndicator> indicators = new ArrayList<>();
        
        for (Document pattern : patterns) {
            try {
                Map<String, Object> metadata = pattern.getMetadata();
                
                ThreatIndicator indicator = new ThreatIndicator();
                indicator.setIndicatorId(UUID.randomUUID().toString());
                indicator.setType(extractIndicatorType(metadata));
                indicator.setValue(extractIndicatorValue(metadata, pattern));
                indicator.setSeverity(extractSeverity(metadata));
                indicator.setConfidence(extractConfidenceScore(metadata));
                indicator.setDescription(createIndicatorDescription(metadata, pattern));
                indicator.setDetectedAt(LocalDateTime.now());
                indicator.setSource("VectorStore");
                
                indicators.add(indicator);
                
            } catch (Exception e) {
                log.warn("Error creating indicator from pattern", e);
            }
        }
        
        return indicators;
    }
    
    private ThreatIndicator.IndicatorType extractIndicatorType(Map<String, Object> metadata) {
        Object type = metadata.get("threat_type");
        if (type != null) {
            try {
                return ThreatIndicator.IndicatorType.valueOf(type.toString().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ThreatIndicator.IndicatorType.PATTERN;
            }
        }
        return ThreatIndicator.IndicatorType.PATTERN;
    }
    
    private String extractIndicatorValue(Map<String, Object> metadata, Document pattern) {
        Object similarity = metadata.get("similarity");
        if (similarity != null) {
            return "similarity:" + similarity;
        }
        return "pattern_content:" + pattern.getText().substring(0, Math.min(100, pattern.getText().length()));
    }
    
    private ThreatIndicator.Severity extractSeverity(Map<String, Object> metadata) {
        Object severity = metadata.get("severity");
        if (severity != null) {
            try {
                return ThreatIndicator.Severity.valueOf(severity.toString().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ThreatIndicator.Severity.MEDIUM;
            }
        }
        return ThreatIndicator.Severity.MEDIUM;
    }
    
    private Double extractConfidenceScore(Map<String, Object> metadata) {
        Object confidence = metadata.get("confidence");
        if (confidence instanceof Number) {
            return ((Number) confidence).doubleValue();
        }
        // AI Native: 기본값 제거, LLM이 결정해야 함
        return Double.NaN;
    }
    
    private String createIndicatorDescription(Map<String, Object> metadata, Document pattern) {
        return String.format("Similar pattern found with metadata: %s", 
            metadata.entrySet().stream()
                .limit(3)
                .map(e -> e.getKey() + ":" + e.getValue())
                .collect(Collectors.joining(", ")));
    }
    
    // AI Native: 규칙 기반 가중치 적용 제거
    // private double getIndicatorWeight(ThreatIndicator indicator) { ... }

    // AI Native: 임계값 기반 ThreatLevel 매핑 제거
    // LLM이 ThreatLevel을 직접 결정해야 함
    // private ThreatAssessment.ThreatLevel determineThreatLevel(double riskScore) { ... }

    // AI Native: 규칙 기반 신뢰도 계산 제거
    // private double calculatePatternConfidence(List<Document> patterns) { ... }

    // AI Native: 규칙 기반 컨텍스트 조정 메서드들 제거
    // - calculateContextAdjustment(): Trust Score 기반 조정 제거
    // - extractContextIndicators(): 임계값 기반 지표 추출 제거
    // - getContextBasedActions(): 임계값 기반 액션 제거
    // - calculateContextConfidence(): 규칙 기반 신뢰도 계산 제거
    
    private Map<String, Object> createMetadata(SecurityEvent event, List<Document> patterns) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("strategy", getStrategyName());
        metadata.put("pattern_count", patterns.size());
        // AI Native v4.0.0: eventType 제거 - severity 기반
        metadata.put("severity", event.getSeverity() != null ? event.getSeverity().toString() : "INFO");
        metadata.put("evaluation_time", LocalDateTime.now().toString());
        
        if (!patterns.isEmpty()) {
            metadata.put("top_similarity", patterns.get(0).getMetadata().get("similarity"));
        }
        
        return metadata;
    }
    
    private Map<String, Object> createContextMetadata(SecurityEvent event, SecurityContext context, 
                                                    List<Document> contextPatterns, ThreatAssessment basicAssessment) {
        Map<String, Object> metadata = createMetadata(event, contextPatterns);
        metadata.put("context_enabled", true);
        metadata.put("trust_score", context.getTrustScore());
        metadata.put("context_patterns", contextPatterns.size());
        metadata.put("basic_risk_score", basicAssessment.getRiskScore());
        return metadata;
    }
    
    private List<String> convertToStringList(List<ThreatIndicator> indicators) {
        return indicators.stream()
            .map(indicator -> indicator.getType() + ":" + indicator.getValue())
            .collect(Collectors.toList());
    }
    
    private ThreatAssessment createFallbackAssessment(SecurityEvent event) {
        // AI Native: 규칙 기반 기본값 제거, LLM 분석 필요 표시
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName() + "-Fallback")
            .riskScore(Double.NaN)  // AI Native: LLM이 결정해야 함
            .indicators(List.of("VECTORSTORE_UNAVAILABLE"))
            .recommendedActions(List.of("LLM_ANALYSIS_REQUIRED"))
            .confidence(Double.NaN)  // AI Native: LLM이 결정해야 함
            // AI Native v3.1: metadata 필드 제거됨 - 죽은 필드
            .action("ESCALATE")  // AI Native: LLM 분석 필요
            .build();
    }

    private ThreatAssessment createErrorAssessment(SecurityEvent event, Exception error) {
        // AI Native: 에러 시에도 규칙 기반 기본값 사용 안 함
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName() + "-Error")
            .riskScore(Double.NaN)  // AI Native: LLM이 결정해야 함
            .indicators(List.of("EVALUATION_ERROR"))
            .recommendedActions(List.of("LLM_ANALYSIS_REQUIRED", "MANUAL_REVIEW"))
            .confidence(Double.NaN)  // AI Native: LLM이 결정해야 함
            // AI Native v3.1: metadata 필드 제거됨 - 죽은 필드
            .action("ESCALATE")  // AI Native: LLM 분석 필요
            .build();
    }
}