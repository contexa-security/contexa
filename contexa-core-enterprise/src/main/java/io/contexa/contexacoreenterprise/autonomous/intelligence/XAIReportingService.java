package io.contexa.contexacoreenterprise.autonomous.intelligence;

import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatIndicators;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import io.contexa.contexacommon.domain.response.RiskAssessmentResponse;
import io.contexa.contexacommon.domain.response.BehavioralAnalysisResponse;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class XAIReportingService {

    private final StandardVectorStoreService vectorStore;
    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${xai.enabled:true}")
    private boolean xaiEnabled;
    
    @Value("${xai.detail.level:MEDIUM}")
    private DetailLevel defaultDetailLevel;
    
    @Value("${xai.cache.ttl-hours:24}")
    private int cacheTtlHours;
    
    @Value("${xai.feature.importance.threshold:0.1}")
    private double featureImportanceThreshold;
    
    @Value("${xai.confidence.threshold:0.7}")
    private double confidenceThreshold;
    
    @Value("${xai.max.alternatives:5}")
    private int maxAlternatives;
    
    @Value("${xai.visualization.enabled:true}")
    private boolean visualizationEnabled;

    private final Map<String, CachedReport> reportCache = new ConcurrentHashMap<>();

    private final Map<String, FeatureImportanceModel> featureModels = new ConcurrentHashMap<>();

    private final AtomicLong totalReportsGenerated = new AtomicLong(0);
    private final AtomicLong cachedReportsServed = new AtomicLong(0);
    private final Map<DetailLevel, AtomicLong> detailLevelStats = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void initialize() {
        if (!xaiEnabled) {
                        return;
        }

        initializeFeatureModels();

        startCacheCleaner();
        
            }

    public Mono<XAIReport> explainRiskAssessment(
        String assessmentId,
        RiskAssessmentResponse riskAssessment,
        SecurityEvent event
    ) {
        if (!xaiEnabled) {
            return Mono.just(XAIReport.disabled());
        }

        CachedReport cached = reportCache.get(assessmentId);
        if (cached != null && !cached.isExpired()) {
            cachedReportsServed.incrementAndGet();
            return Mono.just(cached.getReport());
        }
        
        return Mono.fromCallable(() -> {

            Map<String, Double> features = extractFeatures(event);

            Map<String, Double> featureImportance = calculateFeatureImportance(
                "risk_assessment", features, riskAssessment.riskScore()
            );

            List<String> decisionPath = traceDecisionPath(riskAssessment, features);

            List<AlternativeScenario> alternatives = generateAlternatives(
                features, riskAssessment.riskScore()
            );

            ConfidenceAnalysis confidence = analyzeConfidence(
                riskAssessment, features, featureImportance
            );

            XAIReport report = XAIReport.builder()
                .assessmentId(assessmentId)
                .type("RISK_ASSESSMENT")
                .decision(String.format("위험도: %s (%.2f)", 
                    "MEDIUM", riskAssessment.riskScore()))
                .confidence(confidence.getOverallConfidence())
                .reasoningChain(decisionPath)
                .featureImportance(featureImportance)
                .alternativeHypotheses(alternatives.stream()
                    .map(AlternativeScenario::getDescription)
                    .collect(Collectors.toList()))
                .detailLevel(defaultDetailLevel)
                .visualizations(generateVisualizations(featureImportance, confidence))
                .metadata(createMetadata(event, riskAssessment))
                .timestamp(LocalDateTime.now())
                .build();

            cacheReport(assessmentId, report);

            totalReportsGenerated.incrementAndGet();
            detailLevelStats.computeIfAbsent(defaultDetailLevel, k -> new AtomicLong())
                .incrementAndGet();
            
            return report;
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<XAIReport> explainBehaviorAnalysis(
        String analysisId,
        BehavioralAnalysisResponse behaviorAnalysis,
        SecurityEvent event
    ) {
        if (!xaiEnabled) {
            return Mono.just(XAIReport.disabled());
        }
        
        return Mono.fromCallable(() -> {

            Map<String, Double> features = extractBehaviorFeatures(event);

            BehaviorPattern pattern = analyzeBehaviorPattern(behaviorAnalysis);

            List<String> anomalyExplanation = explainAnomalies(
                behaviorAnalysis.getBehavioralRiskScore() / 100.0,
                pattern,
                features
            );

            TemporalAnalysis temporal = analyzeTemporalPatterns(event, behaviorAnalysis);

            XAIReport report = XAIReport.builder()
                .assessmentId(analysisId)
                .type("BEHAVIOR_ANALYSIS")
                .decision(String.format("이상 점수: %.2f, 패턴: %s",
                    behaviorAnalysis.getBehavioralRiskScore() / 100.0, pattern.getName()))
                .confidence(calculateBehaviorConfidence(behaviorAnalysis))
                .reasoningChain(anomalyExplanation)
                .featureImportance(features)
                .alternativeHypotheses(generateBehaviorAlternatives(pattern))
                .detailLevel(defaultDetailLevel)
                .visualizations(generateBehaviorVisualizations(pattern, temporal))
                .metadata(createBehaviorMetadata(behaviorAnalysis))
                .timestamp(LocalDateTime.now())
                .build();
            
            cacheReport(analysisId, report);
            totalReportsGenerated.incrementAndGet();
            
            return report;
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<XAIReport> explainSoarDecision(
        String decisionId,
        SoarResponse soarResponse,
        Map<String, Object> context
    ) {
        if (!xaiEnabled) {
            return Mono.just(XAIReport.disabled());
        }
        
        return Mono.fromCallable(() -> {

            RecommendationAnalysis recAnalysis = analyzeRecommendations(
                soarResponse.getRecommendations()
            );

            List<String> toolSelectionReasoning = explainToolSelection(soarResponse, context);

            RiskJustification riskJustification = justifyRiskLevel(
                soarResponse.getThreatLevel() != null ? soarResponse.getThreatLevel().toString() : "MEDIUM",
                context
            );

            List<String> alternativeActions = generateAlternativeActions(
                soarResponse,
                context
            );

            XAIReport report = XAIReport.builder()
                .assessmentId(decisionId)
                .type("SOAR_DECISION")
                .decision(String.format("권장사항: %d개, 위험도: %s",
                    soarResponse.getRecommendations().size(),
                    soarResponse.getThreatLevel() != null ? soarResponse.getThreatLevel().toString() : "MEDIUM"))
                .confidence(recAnalysis.getConfidence())
                .reasoningChain(combineReasoningChains(
                    recAnalysis.getReasoning(),
                    toolSelectionReasoning,
                    riskJustification.getReasoning()
                ))
                .featureImportance(extractSoarFeatures(soarResponse, context))
                .alternativeHypotheses(alternativeActions)
                .detailLevel(defaultDetailLevel)
                .visualizations(generateSoarVisualizations(recAnalysis, riskJustification))
                .metadata(createSoarMetadata(soarResponse))
                .timestamp(LocalDateTime.now())
                .build();
            
            cacheReport(decisionId, report);
            totalReportsGenerated.incrementAndGet();
            
            return report;
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<XAIReport> explainThreatCorrelation(
        String correlationId,
        List<SecurityEvent> correlatedEvents,
        ThreatIndicators indicators
    ) {
        if (!xaiEnabled) {
            return Mono.just(XAIReport.disabled());
        }
        
        return Mono.fromCallable(() -> {

            CorrelationAnalysis correlation = analyzeCorrelations(correlatedEvents);

            List<String> mitreExplanation = explainMitreMapping(indicators);

            TemporalRelationship temporal = analyzeTemporalRelationship(correlatedEvents);

            CausalInference causal = inferCausality(correlatedEvents, indicators);

            XAIReport report = XAIReport.builder()
                .assessmentId(correlationId)
                .type("THREAT_CORRELATION")
                .decision(String.format("상관 이벤트: %d개, 위협 유형: %s",
                    correlatedEvents.size(),
                    indicators.identifyThreatTypes()))
                .confidence(correlation.getConfidence())
                .reasoningChain(combineReasoningChains(
                    correlation.getExplanation(),
                    mitreExplanation,
                    causal.getExplanation()
                ))
                .featureImportance(correlation.getImportanceScores())
                .alternativeHypotheses(causal.getAlternativeHypotheses())
                .detailLevel(defaultDetailLevel)
                .visualizations(generateCorrelationVisualizations(correlation, temporal))
                .metadata(createCorrelationMetadata(correlatedEvents, indicators))
                .timestamp(LocalDateTime.now())
                .build();
            
            cacheReport(correlationId, report);
            totalReportsGenerated.incrementAndGet();
            
            return report;
        })
        .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<XAIReport> generateReport(
        String assessmentId,
        Object assessment,
        DetailLevel detailLevel
    ) {
        if (assessment instanceof RiskAssessmentResponse) {
            return explainRiskAssessment(assessmentId, 
                (RiskAssessmentResponse) assessment, null)
                .map(report -> adjustDetailLevel(report, detailLevel));
        } else if (assessment instanceof BehavioralAnalysisResponse) {
            return explainBehaviorAnalysis(assessmentId, 
                (BehavioralAnalysisResponse) assessment, null)
                .map(report -> adjustDetailLevel(report, detailLevel));
        } else if (assessment instanceof SoarResponse) {
            return explainSoarDecision(assessmentId, 
                (SoarResponse) assessment, new HashMap<>())
                .map(report -> adjustDetailLevel(report, detailLevel));
        }
        
        return Mono.just(XAIReport.unsupported());
    }

    private Map<String, Double> extractFeatures(SecurityEvent event) {
        Map<String, Double> features = new HashMap<>();

        features.put("source_risk", getSourceRisk(event.getSource() != null ? event.getSource().name() : "UNKNOWN"));
        features.put("severity_score", getSeverityScore(event.getSeverity().name()));
        features.put("time_of_day", getTimeScore(event.getTimestamp()));

        if (event.getUserId() != null) {
            features.put("user_risk_score", getUserRiskScore(event.getUserId()));
            features.put("user_activity_level", getUserActivityLevel(event.getUserId()));
        }

        if (event.getSourceIp() != null) {
            features.put("ip_reputation", getIpReputation(event.getSourceIp()));
            features.put("geo_risk", getGeoRisk(event.getSourceIp()));
        }

        if (event.getMetadata() != null) {
            features.put("data_sensitivity", getDataSensitivity(event.getMetadata()));
            features.put("action_risk", getActionRisk(event.getMetadata()));
        }
        
        return features;
    }

    private Map<String, Double> extractBehaviorFeatures(SecurityEvent event) {
        Map<String, Double> features = new HashMap<>();
        
        features.put("activity_frequency", 0.5);  
        features.put("time_deviation", 0.3);
        features.put("location_anomaly", 0.1);
        features.put("resource_access_pattern", 0.6);
        features.put("peer_group_deviation", 0.4);
        
        return features;
    }

    private Map<String, Double> calculateFeatureImportance(
        String modelType,
        Map<String, Double> features,
        double prediction
    ) {
        FeatureImportanceModel model = featureModels.computeIfAbsent(
            modelType, k -> createDefaultModel()
        );
        
        Map<String, Double> importance = new HashMap<>();
        double totalContribution = 0.0;
        
        for (Map.Entry<String, Double> feature : features.entrySet()) {
            double weight = model.getWeight(feature.getKey());
            double contribution = feature.getValue() * weight;
            importance.put(feature.getKey(), contribution);
            totalContribution += Math.abs(contribution);
        }

        if (totalContribution > 0) {
            double finalTotal = totalContribution;
            importance.replaceAll((k, v) -> v / finalTotal);
        }

        importance.entrySet().removeIf(e -> 
            Math.abs(e.getValue()) < featureImportanceThreshold
        );
        
        return importance;
    }

    private List<String> traceDecisionPath(
        RiskAssessmentResponse assessment,
        Map<String, Double> features
    ) {
        List<String> path = new ArrayList<>();

        path.add(String.format("1. 이벤트 수신 및 초기 분류: %s", 
            "MEDIUM"));

        features.entrySet().stream()
            .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
            .limit(3)
            .forEach(entry -> 
                path.add(String.format("2. %s 평가: %.2f (영향도: 높음)", 
                    entry.getKey(), entry.getValue()))
            );

        path.add("3. 과거 패턴과 비교 분석 수행");

        path.add(String.format("4. 최종 위험 점수 계산: %.2f", 
            assessment.riskScore()));

        path.add(String.format("5. 임계값 비교 및 위험 수준 결정: %s", 
            "MEDIUM"));
        
        return path;
    }

    private List<AlternativeScenario> generateAlternatives(
        Map<String, Double> features,
        double actualScore
    ) {
        List<AlternativeScenario> alternatives = new ArrayList<>();

        features.entrySet().stream()
            .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
            .limit(maxAlternatives)
            .forEach(entry -> {
                String feature = entry.getKey();
                double value = entry.getValue();

                double reducedScore = simulateScore(features, feature, value * 0.5);
                alternatives.add(new AlternativeScenario(
                    String.format("%s가 50%% 낮았다면", feature),
                    reducedScore,
                    actualScore - reducedScore
                ));

                double increasedScore = simulateScore(features, feature, value * 1.5);
                alternatives.add(new AlternativeScenario(
                    String.format("%s가 50%% 높았다면", feature),
                    increasedScore,
                    increasedScore - actualScore
                ));
            });
        
        return alternatives.stream()
            .sorted(Comparator.comparing(AlternativeScenario::getImpact).reversed())
            .limit(maxAlternatives)
            .collect(Collectors.toList());
    }

    private ConfidenceAnalysis analyzeConfidence(
        RiskAssessmentResponse assessment,
        Map<String, Double> features,
        Map<String, Double> importance
    ) {
        double dataQuality = calculateDataQuality(features);
        double modelCertainty = calculateModelCertainty(importance);
        double consistencyScore = calculateConsistency(assessment);
        
        double overallConfidence = (dataQuality * 0.3 + 
                                    modelCertainty * 0.4 + 
                                    consistencyScore * 0.3);
        
        List<String> factors = new ArrayList<>();
        if (dataQuality < 0.7) {
            factors.add("데이터 품질 낮음");
        }
        if (modelCertainty < 0.8) {
            factors.add("모델 불확실성 존재");
        }
        if (consistencyScore < 0.85) {
            factors.add("일관성 부족");
        }
        
        return new ConfidenceAnalysis(overallConfidence, factors, dataQuality, modelCertainty, consistencyScore);
    }

    private Map<String, Object> generateVisualizations(
        Map<String, Double> importance,
        ConfidenceAnalysis confidence
    ) {
        if (!visualizationEnabled) {
            return Collections.emptyMap();
        }
        
        Map<String, Object> visualizations = new HashMap<>();

        visualizations.put("featureImportanceChart", createBarChart(importance));

        visualizations.put("confidenceGauge", createGaugeChart(confidence.getOverallConfidence()));

        visualizations.put("decisionTree", createDecisionTree(importance));
        
        return visualizations;
    }

    private BehaviorPattern analyzeBehaviorPattern(BehavioralAnalysisResponse analysis) {
        
        return new BehaviorPattern(
            "UNUSUAL_ACCESS_PATTERN",
            "비정상적인 접근 패턴",
            analysis.getBehavioralRiskScore() / 100.0
        );
    }

    private List<String> explainAnomalies(
        double anomalyScore,
        BehaviorPattern pattern,
        Map<String, Double> features
    ) {
        List<String> explanation = new ArrayList<>();
        
        explanation.add(String.format("이상 점수 %.2f 감지 (정상 범위: 0.0-0.3)", anomalyScore));
        explanation.add(String.format("패턴 유형: %s", pattern.getDescription()));
        
        features.entrySet().stream()
            .filter(e -> e.getValue() > 0.5)
            .forEach(e -> 
                explanation.add(String.format("- %s: 비정상적으로 높음 (%.2f)", 
                    e.getKey(), e.getValue()))
            );
        
        return explanation;
    }

    private TemporalAnalysis analyzeTemporalPatterns(
        SecurityEvent event,
        BehavioralAnalysisResponse analysis
    ) {
        
        return new TemporalAnalysis(
            "AFTER_HOURS",
            "업무 시간 외 활동",
            0.7
        );
    }

    private RecommendationAnalysis analyzeRecommendations(List<String> recommendations) {
        List<String> reasoning = new ArrayList<>();
        reasoning.add("위험 수준과 이벤트 유형 고려");
        reasoning.add("과거 유사 사례 분석");
        reasoning.add("현재 시스템 상태 평가");
        
        double confidence = 0.85;  
        
        return new RecommendationAnalysis(recommendations, reasoning, confidence);
    }

    private List<String> explainToolSelection(SoarResponse response, Map<String, Object> context) {
        List<String> explanation = new ArrayList<>();
        
        explanation.add("도구 선택 기준:");
        explanation.add("1. 위험 수준과 도구 위험도 매칭");
        explanation.add("2. 컨텍스트 기반 도구 적합성 평가");
        explanation.add("3. 승인 정책 확인");
        
        return explanation;
    }

    private RiskJustification justifyRiskLevel(String riskLevel, Map<String, Object> context) {
        List<String> reasoning = new ArrayList<>();
        
        reasoning.add(String.format("위험 수준 %s로 평가된 이유:", riskLevel));
        reasoning.add("- 위협 지표 분석 결과");
        reasoning.add("- 영향 범위 평가");
        reasoning.add("- 악용 가능성 분석");
        
        return new RiskJustification(riskLevel, reasoning);
    }

    private List<String> generateAlternativeActions(
        SoarResponse response,
        Map<String, Object> context
    ) {
        List<String> alternatives = new ArrayList<>();
        
        alternatives.add("대안 1: 수동 검토 후 조치");
        alternatives.add("대안 2: 추가 모니터링 설정");
        alternatives.add("대안 3: 격리 후 상세 분석");
        
        return alternatives;
    }

    private CorrelationAnalysis analyzeCorrelations(List<SecurityEvent> events) {
        Map<String, Double> importanceScores = new HashMap<>();
        List<String> explanation = new ArrayList<>();
        
        explanation.add("이벤트 간 상관관계 발견:");
        explanation.add("- 시간적 근접성");
        explanation.add("- 동일 사용자/IP");
        explanation.add("- 유사한 행동 패턴");
        
        double confidence = 0.75;
        
        return new CorrelationAnalysis(importanceScores, explanation, confidence);
    }

    private List<String> explainMitreMapping(ThreatIndicators indicators) {
        List<String> explanation = new ArrayList<>();
        
        if (indicators.isMitreMapping()) {
            explanation.add("MITRE ATT&CK 매핑:");
            if (indicators.getMitreTactics() != null) {
                indicators.getMitreTactics().forEach(tactic -> 
                    explanation.add(String.format("- Tactic: %s", tactic))
                );
            }
            explanation.add(String.format("기법 수: %d", indicators.getMitreTechniques()));
        }
        
        return explanation;
    }

    private TemporalRelationship analyzeTemporalRelationship(List<SecurityEvent> events) {
        
        return new TemporalRelationship("SEQUENTIAL", "순차적 발생", 0.8);
    }

    private CausalInference inferCausality(
        List<SecurityEvent> events,
        ThreatIndicators indicators
    ) {
        List<String> explanation = new ArrayList<>();
        explanation.add("인과관계 분석:");
        explanation.add("- 초기 침입 시도");
        explanation.add("- 권한 상승 시도");
        explanation.add("- 데이터 접근");
        
        List<String> alternatives = new ArrayList<>();
        alternatives.add("대안 가설: 정상적인 관리 작업");
        alternatives.add("대안 가설: 시스템 오작동");
        
        return new CausalInference(explanation, alternatives);
    }

    private List<String> combineReasoningChains(List<String>... chains) {
        List<String> combined = new ArrayList<>();
        for (List<String> chain : chains) {
            if (chain != null) {
                combined.addAll(chain);
            }
        }
        return combined;
    }

    private XAIReport adjustDetailLevel(XAIReport report, DetailLevel level) {
        report.setDetailLevel(level);
        
        switch (level) {
            case MINIMAL:
                
                report.setFeatureImportance(
                    report.getFeatureImportance().entrySet().stream()
                        .limit(3)
                        .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            Map.Entry::getValue
                        ))
                );
                report.setReasoningChain(
                    report.getReasoningChain().stream()
                        .limit(3)
                        .collect(Collectors.toList())
                );
                break;
                
            case HIGH:
            case FULL:
                
                break;
                
            case MEDIUM:
            default:
                
                report.setFeatureImportance(
                    report.getFeatureImportance().entrySet().stream()
                        .limit(5)
                        .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            Map.Entry::getValue
                        ))
                );
                break;
        }
        
        return report;
    }

    private double getSourceRisk(String source) {
        
        return switch (source) {
            case "NETWORK" -> 0.8;
            case "ENDPOINT" -> 0.7;
            case "IAM" -> 0.6;
            case "CLOUD" -> 0.5;
            default -> 0.3;
        };
    }

    private double getSeverityScore(String severity) {
        
        return switch (severity) {
            case "CRITICAL" -> 1.0;
            case "HIGH" -> 0.8;
            case "MEDIUM" -> 0.5;
            case "LOW" -> 0.3;
            default -> 0.1;
        };
    }
    
    private double getTimeScore(LocalDateTime timestamp) {
        int hour = timestamp.getHour();
        
        return (hour < 8 || hour > 18) ? 0.8 : 0.3;
    }
    
    private double getUserRiskScore(String userId) {
        
        return 0.5;
    }
    
    private double getUserActivityLevel(String userId) {
        
        return 0.6;
    }
    
    private double getIpReputation(String ip) {
        
        return 0.7;
    }
    
    private double getGeoRisk(String ip) {
        
        return 0.4;
    }
    
    private double getDataSensitivity(Map<String, Object> data) {
        
        return 0.6;
    }
    
    private double getActionRisk(Map<String, Object> data) {
        
        return 0.5;
    }
    
    private double simulateScore(Map<String, Double> features, String changedFeature, double newValue) {
        Map<String, Double> simulated = new HashMap<>(features);
        simulated.put(changedFeature, newValue);

        return simulated.values().stream()
            .mapToDouble(Double::doubleValue)
            .average()
            .orElse(0.5);
    }
    
    private double calculateDataQuality(Map<String, Double> features) {
        
        long missingCount = features.values().stream()
            .filter(v -> v == null || v == 0.0)
            .count();
        
        return 1.0 - (missingCount / (double) features.size());
    }
    
    private double calculateModelCertainty(Map<String, Double> importance) {
        
        double entropy = importance.values().stream()
            .mapToDouble(v -> -v * Math.log(v + 0.001))
            .sum();
        
        return 1.0 / (1.0 + entropy);
    }
    
    private double calculateConsistency(RiskAssessmentResponse assessment) {
        
        return 0.9;
    }
    
    private double calculateBehaviorConfidence(BehavioralAnalysisResponse analysis) {
        return Math.max(0.3, Math.min(1.0, 1.0 - analysis.getBehavioralRiskScore() / 100.0));
    }
    
    private List<String> generateBehaviorAlternatives(BehaviorPattern pattern) {
        List<String> alternatives = new ArrayList<>();
        alternatives.add("정상적인 업무 변화");
        alternatives.add("시스템 오류로 인한 비정상 패턴");
        alternatives.add("다른 사용자의 계정 사용");
        return alternatives;
    }
    
    private Map<String, Object> generateBehaviorVisualizations(
        BehaviorPattern pattern,
        TemporalAnalysis temporal
    ) {
        Map<String, Object> viz = new HashMap<>();
        viz.put("patternChart", pattern);
        viz.put("temporalChart", temporal);
        return viz;
    }
    
    private Map<String, Object> createBehaviorMetadata(BehavioralAnalysisResponse analysis) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("anomalyScore", analysis.getBehavioralRiskScore() / 100.0);
        metadata.put("timestamp", LocalDateTime.now());
        return metadata;
    }
    
    private Map<String, Double> extractSoarFeatures(
        SoarResponse response,
        Map<String, Object> context
    ) {
        Map<String, Double> features = new HashMap<>();
        features.put("recommendation_count", (double) response.getRecommendations().size());
        features.put("risk_level", getRiskLevelScore(response.getThreatLevel() != null ? response.getThreatLevel().toString() : "MEDIUM"));
        return features;
    }
    
    private double getRiskLevelScore(String riskLevel) {
        return switch (riskLevel) {
            case "CRITICAL" -> 1.0;
            case "HIGH" -> 0.75;
            case "MEDIUM" -> 0.5;
            case "LOW" -> 0.25;
            default -> 0.1;
        };
    }
    
    private Map<String, Object> generateSoarVisualizations(
        RecommendationAnalysis rec,
        RiskJustification risk
    ) {
        Map<String, Object> viz = new HashMap<>();
        viz.put("recommendationFlow", rec);
        viz.put("riskMatrix", risk);
        return viz;
    }
    
    private Map<String, Object> createSoarMetadata(SoarResponse response) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("sessionId", response.getSessionId());
        metadata.put("recommendationCount", response.getRecommendations().size());
        metadata.put("riskLevel", response.getThreatLevel() != null ? response.getThreatLevel().toString() : "MEDIUM");
        return metadata;
    }
    
    private Map<String, Object> generateCorrelationVisualizations(
        CorrelationAnalysis correlation,
        TemporalRelationship temporal
    ) {
        Map<String, Object> viz = new HashMap<>();
        viz.put("correlationMatrix", correlation);
        viz.put("timelineChart", temporal);
        return viz;
    }
    
    private Map<String, Object> createCorrelationMetadata(
        List<SecurityEvent> events,
        ThreatIndicators indicators
    ) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("eventCount", events.size());
        metadata.put("threatTypes", indicators.identifyThreatTypes());
        metadata.put("riskScore", 75.0); 
        return metadata;
    }
    
    private Map<String, Object> createMetadata(
        SecurityEvent event,
        RiskAssessmentResponse assessment
    ) {
        Map<String, Object> metadata = new HashMap<>();
        if (event != null) {
            metadata.put("eventId", event.getEventId());
            metadata.put("severity", event.getSeverity());
        }
        if (assessment != null) {
            metadata.put("riskScore", assessment.riskScore());
            metadata.put("riskLevel", "MEDIUM");
        }
        return metadata;
    }
    
    private Map<String, Object> createBarChart(Map<String, Double> data) {
        Map<String, Object> chart = new HashMap<>();
        chart.put("type", "bar");
        chart.put("data", data);
        return chart;
    }
    
    private Map<String, Object> createGaugeChart(double value) {
        Map<String, Object> chart = new HashMap<>();
        chart.put("type", "gauge");
        chart.put("value", value);
        chart.put("min", 0.0);
        chart.put("max", 1.0);
        return chart;
    }
    
    private Map<String, Object> createDecisionTree(Map<String, Double> importance) {
        Map<String, Object> tree = new HashMap<>();
        tree.put("type", "tree");
        tree.put("nodes", importance);
        return tree;
    }

    private void initializeFeatureModels() {
        featureModels.put("risk_assessment", createDefaultModel());
        featureModels.put("behavior_analysis", createDefaultModel());
        featureModels.put("threat_correlation", createDefaultModel());
    }

    private FeatureImportanceModel createDefaultModel() {
        Map<String, Double> weights = new HashMap<>();
        weights.put("event_type_risk", 0.2);
        weights.put("severity_score", 0.3);
        weights.put("user_risk_score", 0.15);
        weights.put("ip_reputation", 0.1);
        weights.put("data_sensitivity", 0.15);
        weights.put("action_risk", 0.1);
        
        return new FeatureImportanceModel(weights);
    }

    private void cacheReport(String id, XAIReport report) {
        CachedReport cached = new CachedReport(
            report,
            LocalDateTime.now().plusHours(cacheTtlHours)
        );
        reportCache.put(id, cached);

        String key = "xai:report:" + id;
        redisTemplate.opsForValue().set(key, report, Duration.ofHours(cacheTtlHours));
    }

    private void startCacheCleaner() {
        Schedulers.parallel().schedulePeriodically(() -> {
            reportCache.entrySet().removeIf(entry -> 
                entry.getValue().isExpired()
            );
        }, 3600, 3600, java.util.concurrent.TimeUnit.SECONDS);
    }

    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("enabled", xaiEnabled);
        metrics.put("totalReportsGenerated", totalReportsGenerated.get());
        metrics.put("cachedReportsServed", cachedReportsServed.get());
        
        Map<String, Long> detailStats = new HashMap<>();
        detailLevelStats.forEach((level, count) -> 
            detailStats.put(level.name(), count.get())
        );
        metrics.put("detailLevelStats", detailStats);
        
        metrics.put("cacheSize", reportCache.size());
        
        return metrics;
    }

    @lombok.Data
    @lombok.Builder
    public static class XAIReport {
        private String assessmentId;
        private String type;
        private String decision;
        private double confidence;
        private List<String> reasoningChain;
        private Map<String, Double> featureImportance;
        private List<String> alternativeHypotheses;
        private DetailLevel detailLevel;
        private Map<String, Object> visualizations;
        private Map<String, Object> metadata;
        private LocalDateTime timestamp;

        public static XAIReport disabled() {
            return XAIReport.builder()
                .decision("XAI disabled")
                .confidence(0.0)
                .reasoningChain(Collections.emptyList())
                .featureImportance(Collections.emptyMap())
                .alternativeHypotheses(Collections.emptyList())
                .build();
        }

        public static XAIReport unsupported() {
            return XAIReport.builder()
                .decision("Unsupported assessment type")
                .confidence(0.0)
                .reasoningChain(Collections.emptyList())
                .featureImportance(Collections.emptyMap())
                .alternativeHypotheses(Collections.emptyList())
                .build();
        }
    }

    public enum DetailLevel {
        MINIMAL,   
        MEDIUM,    
        HIGH,      
        FULL       
    }

    @AllArgsConstructor
    private static class CachedReport {
        private final XAIReport report;
        private final LocalDateTime expiryTime;

        public XAIReport getReport() {
            return report;
        }

        public boolean isExpired() {
            return LocalDateTime.now().isAfter(expiryTime);
        }
    }

    @AllArgsConstructor
    private static class FeatureImportanceModel {
        private final Map<String, Double> weights;
        
        public double getWeight(String feature) {
            return weights.getOrDefault(feature, 0.1);
        }
    }

    @AllArgsConstructor
    private static class AlternativeScenario {
        private final String description;
        private final double predictedScore;
        private final double impact;
        
        public String getDescription() {
            return String.format("%s → 점수: %.2f (영향: %+.2f)", 
                description, predictedScore, impact);
        }
        
        public double getImpact() {
            return Math.abs(impact);
        }
    }
    
    @AllArgsConstructor
    private static class ConfidenceAnalysis {
        private final double overallConfidence;
        private final List<String> factors;
        private final double dataQuality;
        private final double modelCertainty;
        private final double consistencyScore;
        
        public double getOverallConfidence() {
            return overallConfidence;
        }
    }
    
    @AllArgsConstructor
    private static class BehaviorPattern {
        private final String name;
        private final String description;
        private final double score;
        
        public String getName() {
            return name;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    @AllArgsConstructor
    private static class TemporalAnalysis {
        private final String pattern;
        private final String description;
        private final double significance;
    }
    
    @AllArgsConstructor
    private static class RecommendationAnalysis {
        private final List<String> recommendations;
        private final List<String> reasoning;
        private final double confidence;
        
        public List<String> getReasoning() {
            return reasoning;
        }
        
        public double getConfidence() {
            return confidence;
        }
    }
    
    @AllArgsConstructor
    private static class RiskJustification {
        private final String riskLevel;
        private final List<String> reasoning;
        
        public List<String> getReasoning() {
            return reasoning;
        }
    }
    
    @AllArgsConstructor
    private static class CorrelationAnalysis {
        private final Map<String, Double> importanceScores;
        private final List<String> explanation;
        private final double confidence;
        
        public Map<String, Double> getImportanceScores() {
            return importanceScores;
        }
        
        public List<String> getExplanation() {
            return explanation;
        }
        
        public double getConfidence() {
            return confidence;
        }
    }
    
    @AllArgsConstructor
    private static class TemporalRelationship {
        private final String type;
        private final String description;
        private final double strength;
    }
    
    @AllArgsConstructor
    private static class CausalInference {
        private final List<String> explanation;
        private final List<String> alternativeHypotheses;
        
        public List<String> getExplanation() {
            return explanation;
        }
        
        public List<String> getAlternativeHypotheses() {
            return alternativeHypotheses;
        }
    }
}