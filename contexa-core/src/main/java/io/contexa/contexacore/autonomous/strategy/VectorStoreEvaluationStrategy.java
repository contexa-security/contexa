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
 * Vector Store 기반 위협 평가 전략
 *
 * UnifiedVectorService를 활용하여 과거 패턴과의 유사도 검색을 통해
 * 위협을 평가하는 전략입니다. 기계학습 기반 패턴 매칭을 통해
 * 알려진 위협 패턴과의 유사도를 계산합니다.
 *
 * 핵심 특징:
 * - UnifiedVectorService를 통한 통합된 벡터 검색 (자동 캐싱 및 라우팅)
 * - Vector Store RAG 기반 패턴 검색
 * - 동적 임계값 설정
 * - 컨텍스트 기반 향상된 평가
 * - 객체지향 Strategy 패턴 준수
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class VectorStoreEvaluationStrategy implements ThreatEvaluationStrategy {

    @Autowired(required = false)
    private UnifiedVectorService unifiedVectorService;
    
    private static final String STRATEGY_NAME = "VECTOR_STORE";
    private static final double DEFAULT_SIMILARITY_THRESHOLD = 0.75;
    private static final int DEFAULT_TOP_K = 10;
    
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        try {
            log.debug("Vector Store threat evaluation for event: {}", event.getEventId());
            
            if (unifiedVectorService == null) {
                log.warn("UnifiedVectorService not available, using fallback evaluation");
                return createFallbackAssessment(event);
            }
            
            // 1. 이벤트를 쿼리 텍스트로 변환
            String queryText = buildQueryFromEvent(event);
            
            // 2. Vector Store에서 유사 패턴 검색
            List<Document> similarPatterns = searchSimilarPatterns(queryText);
            
            // 3. 위협 지표 추출
            List<ThreatIndicator> indicators = extractIndicatorsFromPatterns(similarPatterns, event);
            
            // 4. 위험 점수 계산
            double riskScore = calculateRiskScore(indicators);
            
            // 5. 위협 수준 결정
            ThreatAssessment.ThreatLevel threatLevel = determineThreatLevel(riskScore);
            
            // 6. 권장 액션 도출
            List<String> recommendedActions = getRecommendedActions(event);
            
            // 7. 신뢰도 계산
            double confidence = calculatePatternConfidence(similarPatterns);
            
            return ThreatAssessment.builder()
                .eventId(event.getEventId())
                .assessmentId(UUID.randomUUID().toString())
                .assessedAt(LocalDateTime.now())
                .evaluator(getStrategyName())
                .threatLevel(threatLevel)
                .riskScore(riskScore)
                .indicators(convertToStringList(indicators))
                .recommendedActions(recommendedActions)
                .confidence(confidence)
                .metadata(createMetadata(event, similarPatterns))
                .build();
                
        } catch (Exception e) {
            log.error("Error in vector store threat evaluation for event: {}", event.getEventId(), e);
            return createErrorAssessment(event, e);
        }
    }
    
    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        try {
            log.debug("Context-aware vector store evaluation for event: {} with context", event.getEventId());
            
            // 기본 평가 수행
            ThreatAssessment basicAssessment = evaluate(event);

            if (context == null || unifiedVectorService == null) {
                return basicAssessment;
            }
            
            // 컨텍스트 정보를 활용한 향상된 쿼리 생성
            String contextQuery = buildContextQuery(event, context);
            
            // 컨텍스트 기반 추가 패턴 검색
            List<Document> contextPatterns = searchContextPatterns(contextQuery);
            
            // 컨텍스트 조정 값 계산
            double contextAdjustment = calculateContextAdjustment(context, contextPatterns);
            
            // 향상된 위험 점수
            double enhancedRiskScore = Math.min(1.0, basicAssessment.getRiskScore() + contextAdjustment);
            
            // 향상된 위협 수준
            ThreatAssessment.ThreatLevel enhancedThreatLevel = determineThreatLevel(enhancedRiskScore);
            
            // 컨텍스트 기반 지표 추가
            List<String> contextIndicators = extractContextIndicators(context, contextPatterns);
            List<String> allIndicators = new ArrayList<>(basicAssessment.getIndicators());
            allIndicators.addAll(contextIndicators);
            
            // 컨텍스트 기반 액션 추가
            List<String> contextActions = getContextBasedActions(enhancedThreatLevel, context);
            List<String> allActions = new ArrayList<>(basicAssessment.getRecommendedActions());
            allActions.addAll(contextActions);
            
            return ThreatAssessment.builder()
                .eventId(event.getEventId())
                .assessmentId(UUID.randomUUID().toString())
                .assessedAt(LocalDateTime.now())
                .evaluator(getStrategyName() + "-WithContext")
                .threatLevel(enhancedThreatLevel)
                .riskScore(enhancedRiskScore)
                .indicators(allIndicators)
                .recommendedActions(allActions)
                .confidence(calculateContextConfidence(context, contextPatterns))
                .metadata(createContextMetadata(event, context, contextPatterns, basicAssessment))
                .build();
                
        } catch (Exception e) {
            log.error("Error in context-aware vector store evaluation: {}", e.getMessage(), e);
            // 컨텍스트 평가 실패 시 기본 평가 반환
            return evaluate(event);
        }
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
    
    @Override
    public Map<String, String> mapToFramework(SecurityEvent event) {
        Map<String, String> mapping = new HashMap<>();
        mapping.put("FRAMEWORK", "VECTOR_PATTERN_MATCHING");
        mapping.put("METHOD", "SIMILARITY_SEARCH");
        mapping.put("EVENT_TYPE", event.getEventType().toString());
        mapping.put("ALGORITHM", "COSINE_SIMILARITY");
        return mapping;
    }
    
    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        if (event.getSeverity() == null) {
            return List.of("MONITOR", "LOG");
        }
        
        return switch (event.getSeverity()) {
            case CRITICAL -> List.of("IMMEDIATE_RESPONSE", "ISOLATE_SYSTEM", "ALERT_SOC", "BLOCK_SOURCE");
            case HIGH -> List.of("ESCALATE", "ENHANCE_MONITORING", "INVESTIGATE", "NOTIFY_ADMIN");
            case MEDIUM -> List.of("INVESTIGATE", "MONITOR_CLOSELY", "LOG_ANALYSIS");
            case LOW -> List.of("MONITOR", "LOG", "BASELINE_UPDATE");
            case INFO -> List.of("LOG", "TRACK_METRICS");
            default -> List.of("MONITOR", "LOG");
        };
    }
    
    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        if (indicators.isEmpty()) {
            return 0.2; // 기본 낮은 위험
        }
        
        // 지표별 가중치 적용
        double totalScore = 0.0;
        double totalWeight = 0.0;
        
        for (ThreatIndicator indicator : indicators) {
            double weight = getIndicatorWeight(indicator);
            double score = indicator.getThreatScore() != null ? 
                indicator.getThreatScore() : 0.5;
            
            totalScore += score * weight;
            totalWeight += weight;
        }
        
        return totalWeight > 0 ? Math.min(1.0, totalScore / totalWeight) : 0.2;
    }
    
    @Override
    public boolean canEvaluate(SecurityEvent.EventType eventType) {
        // Vector Store는 모든 이벤트 타입을 패턴 매칭으로 처리 가능
        return unifiedVectorService != null;
    }
    
    @Override
    public int getPriority() {
        return 80; // 중간 우선순위 (기본보다 높음)
    }
    
    // === Private Helper Methods ===
    
    private String buildQueryFromEvent(SecurityEvent event) {
        StringBuilder query = new StringBuilder();
        
        query.append("event_type:").append(event.getEventType());
        
        if (event.getSourceIp() != null) {
            query.append(" source_ip:").append(event.getSourceIp());
        }
        
        if (event.getTargetResource() != null) {
            query.append(" target:").append(event.getTargetResource());
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
        
        if (context.getTrustScore() != null) {
            if (context.getTrustScore() < 0.3) {
                query.append(" low_trust_context");
            } else if (context.getTrustScore() > 0.7) {
                query.append(" high_trust_context");
            }
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
                .similarityThreshold(0.8)
                .build();
                
            return unifiedVectorService.searchSimilar(searchRequest);
        } catch (Exception e) {
            log.error("Error searching context patterns", e);
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
        return 0.7;
    }
    
    private String createIndicatorDescription(Map<String, Object> metadata, Document pattern) {
        return String.format("Similar pattern found with metadata: %s", 
            metadata.entrySet().stream()
                .limit(3)
                .map(e -> e.getKey() + ":" + e.getValue())
                .collect(Collectors.joining(", ")));
    }
    
    private double getIndicatorWeight(ThreatIndicator indicator) {
        if (indicator.getType() == null) {
            return 1.0;
        }
        
        return switch (indicator.getType()) {
            case FILE_HASH, YARA_RULE, BEHAVIORAL -> 3.0;
            case PATTERN, EVENT -> 2.0;
            case IP_ADDRESS, DOMAIN, URL -> 1.5;
            default -> 1.0;
        };
    }
    
    private ThreatAssessment.ThreatLevel determineThreatLevel(double riskScore) {
        if (riskScore >= 0.9) return ThreatAssessment.ThreatLevel.CRITICAL;
        if (riskScore >= 0.7) return ThreatAssessment.ThreatLevel.HIGH;
        if (riskScore >= 0.5) return ThreatAssessment.ThreatLevel.MEDIUM;
        if (riskScore >= 0.3) return ThreatAssessment.ThreatLevel.LOW;
        return ThreatAssessment.ThreatLevel.INFO;
    }
    
    private double calculatePatternConfidence(List<Document> patterns) {
        if (patterns.isEmpty()) {
            return 0.5;
        }
        
        return patterns.stream()
            .mapToDouble(doc -> {
                Object similarity = doc.getMetadata().get("similarity");
                if (similarity instanceof Number) {
                    return ((Number) similarity).doubleValue();
                }
                return 0.7;
            })
            .average()
            .orElse(0.5);
    }
    
    private double calculateContextAdjustment(SecurityContext context, List<Document> contextPatterns) {
        double adjustment = 0.0;
        
        // Trust Score 기반 조정
        if (context.getTrustScore() != null) {
            if (context.getTrustScore() < 0.3) {
                adjustment += 0.2; // 신뢰도 낮으면 위험 증가
            } else if (context.getTrustScore() > 0.8) {
                adjustment -= 0.1; // 신뢰도 높으면 위험 감소
            }
        }
        
        // 컨텍스트 패턴 수 기반 조정
        if (!contextPatterns.isEmpty()) {
            adjustment += Math.min(0.15, contextPatterns.size() * 0.03);
        }
        
        return adjustment;
    }
    
    private List<String> extractContextIndicators(SecurityContext context, List<Document> contextPatterns) {
        List<String> indicators = new ArrayList<>();
        
        if (context.getTrustScore() != null && context.getTrustScore() < 0.3) {
            indicators.add("LOW_TRUST_CONTEXT");
        }
        
        if (!contextPatterns.isEmpty()) {
            indicators.add("CONTEXT_PATTERN_MATCH_COUNT:" + contextPatterns.size());
        }
        
        return indicators;
    }
    
    private List<String> getContextBasedActions(ThreatAssessment.ThreatLevel threatLevel, SecurityContext context) {
        List<String> actions = new ArrayList<>();
        
        if (context.getTrustScore() != null && context.getTrustScore() < 0.2) {
            actions.add("REQUIRE_ADDITIONAL_VERIFICATION");
        }
        
        if (threatLevel == ThreatAssessment.ThreatLevel.CRITICAL) {
            actions.add("CONTEXT_BASED_ISOLATION");
        }
        
        return actions;
    }
    
    private double calculateContextConfidence(SecurityContext context, List<Document> contextPatterns) {
        double baseConfidence = 0.6;
        
        if (context.getTrustScore() != null) {
            baseConfidence += 0.2;
        }
        
        if (!contextPatterns.isEmpty()) {
            baseConfidence += 0.1;
        }
        
        return Math.min(1.0, baseConfidence);
    }
    
    private Map<String, Object> createMetadata(SecurityEvent event, List<Document> patterns) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("strategy", getStrategyName());
        metadata.put("pattern_count", patterns.size());
        metadata.put("event_type", event.getEventType().toString());
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
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName() + "-Fallback")
            .threatLevel(ThreatAssessment.ThreatLevel.MEDIUM)
            .riskScore(0.5)
            .indicators(List.of("FALLBACK_MODE"))
            .recommendedActions(List.of("MONITOR", "LOG"))
            .confidence(0.3)
            .metadata(Map.of("mode", "fallback", "reason", "vectorstore_unavailable"))
            .build();
    }
    
    private ThreatAssessment createErrorAssessment(SecurityEvent event, Exception error) {
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName() + "-Error")
            .threatLevel(ThreatAssessment.ThreatLevel.INFO)
            .riskScore(0.0)
            .indicators(List.of("EVALUATION_ERROR"))
            .recommendedActions(List.of("MANUAL_REVIEW"))
            .confidence(0.0)
            .metadata(Map.of("error", error.getMessage(), "mode", "error"))
            .build();
    }
}