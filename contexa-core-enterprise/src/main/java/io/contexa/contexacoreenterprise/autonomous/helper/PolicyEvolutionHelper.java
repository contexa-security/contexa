package io.contexa.contexacoreenterprise.autonomous.helper;

import io.contexa.contexacore.autonomous.PolicyEvolutionService;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacoreenterprise.autonomous.intelligence.AITuningService;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.rag.service.StandardVectorStoreService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * PolicyEvolutionHelper - 정책 진화 헬퍼
 * 
 * 자율 진화형 정책 패브릭을 지원하는 헬퍼 클래스입니다.
 * SecurityPlaneAgent와 협력하여 정책의 자율적 진화를 담당합니다.
 * 
 * 주요 기능:
 * - 정책 패턴 학습 및 진화
 * - 정책 효과성 평가
 * - 정책 합성 및 최적화
 * - 정책 버전 관리
 * 
 * @since 1.0.0
 */
@Slf4j
@ConditionalOnClass(name = "io.contexa.contexacore.repository.PolicyProposalRepository")
@Component
@RequiredArgsConstructor
public class PolicyEvolutionHelper implements PolicyEvolutionService {

    // 기존 서비스 재사용
    private final UnifiedVectorService unifiedVectorService;
    private final AITuningService aiTuningService;

    @Autowired(required = false)
    private StandardVectorStoreService standardVectorStoreService;

    // Redis Template 주입
    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;
    
    // 설정값
    @Value("${policy.evolution.enabled:true}")
    private boolean evolutionEnabled;
    
    @Value("${policy.evolution.threshold:0.75}")
    private double evolutionThreshold;
    
    @Value("${policy.evolution.min-samples:10}")
    private int minSamplesForEvolution;
    
    @Value("${policy.evolution.retention-days:90}")
    private int policyRetentionDays;
    
    // 정책 저장소
    private final Map<String, EvolvingPolicy> evolvingPolicies = new ConcurrentHashMap<>();
    
    // 정책 버전 히스토리
    private final Map<String, List<PolicyVersion>> policyVersionHistory = new ConcurrentHashMap<>();
    
    // 정책 효과성 메트릭
    private final Map<String, PolicyEffectiveness> effectivenessMetrics = new ConcurrentHashMap<>();
    
    // 통계
    private final AtomicLong totalEvolutions = new AtomicLong(0);
    private final AtomicLong successfulEvolutions = new AtomicLong(0);
    private final AtomicLong policiesGenerated = new AtomicLong(0);
    
    @PostConstruct
    public void initialize() {
        if (!evolutionEnabled) {
            log.info("정책 진화 기능 비활성화됨");
            return;
        }
        
        log.info("PolicyEvolutionHelper 초기화 시작");
        
        // 기존 정책 로드
        loadExistingPolicies();
        
        log.info("PolicyEvolutionHelper 초기화 완료 - {} 개의 정책 로드됨", evolvingPolicies.size());
    }
    
    /**
     * 보안 이벤트로부터 정책 패턴 학습
     *
     * @param event 보안 이벤트
     * @param decision 적용된 결정
     * @param outcome 결과 (성공/실패)
     * @return 학습 결과
     */
    @Override
    public Mono<?> learnFromEvent(
            SecurityEvent event,
            String decision,
            String outcome) {
        
        if (!evolutionEnabled) {
            return Mono.just(PolicyLearningResult.disabled());
        }
        
        return Mono.defer(() -> {
            String policyId = extractPolicyId(event);

            // String outcome을 boolean으로 변환
            boolean result = isPositive(outcome);

            // 정책 효과성 업데이트
            updatePolicyEffectiveness(policyId, result);

            // 진화 필요성 평가
            if (shouldEvolvePolicy(policyId)) {
                return evolvePolicy(policyId, event, decision, result);
            }

            return Mono.just(PolicyLearningResult.recorded(policyId));
        });
    }
    
    /**
     * 정책 진화 (호환성 메서드)
     */
    @Override
    public void evolvePolicy(SecurityEvent event, ThreatAssessment assessment) {
        // 간단한 정책 진화 로직
        if (event != null) {
            String policyId = "POLICY_" + event.getEventType();
            recordPolicyApplication(policyId, event, "AUTO", true);
        }
    }

    /**
     * 정책 적용 기록
     */
    private void recordPolicyApplication(String policyId, SecurityEvent event, String applicationType, boolean success) {
        try {
            Map<String, Object> applicationRecord = new HashMap<>();
            applicationRecord.put("policyId", policyId);
            applicationRecord.put("eventId", event.getEventId());
            applicationRecord.put("eventType", event.getEventType().name());
            applicationRecord.put("applicationType", applicationType);
            applicationRecord.put("success", success);
            applicationRecord.put("timestamp", System.currentTimeMillis());

            // Redis에 기록
            String key = "policy:applications:" + policyId;
            redisTemplate.opsForList().rightPush(key, applicationRecord);

            // 만료 시간 설정 (30일)
            redisTemplate.expire(key, Duration.ofDays(30));

            log.debug("Policy application recorded: {} for event {}", policyId, event.getEventId());
        } catch (Exception e) {
            log.error("Failed to record policy application: {}", policyId, e);
        }
    }

    /**
     * 정책 진화 수행
     */
    private Mono<PolicyLearningResult> evolvePolicy(
            String policyId,
            SecurityEvent event,
            String decision,
            boolean outcome) {
        
        return Mono.defer(() -> {
            EvolvingPolicy policy = evolvingPolicies.computeIfAbsent(
                policyId, k -> new EvolvingPolicy(k)
            );
            
            // 현재 버전 백업
            backupCurrentVersion(policy);
            
            // 정책 파라미터 조정
            adjustPolicyParameters(policy, event, decision, outcome);
            
            // 정책 규칙 합성
            synthesizePolicyRules(policy, event);
            
            // 벡터 스토어에 새 정책 패턴 저장
            savePolicyPattern(policy);
            
            // 통계 업데이트
            totalEvolutions.incrementAndGet();
            if (outcome) {
                successfulEvolutions.incrementAndGet();
            }
            
            log.info("정책 진화 완료: {} (버전 {} -> {})", 
                policyId, policy.getVersion() - 1, policy.getVersion());
            
            return Mono.just(PolicyLearningResult.evolved(policyId, policy.getVersion()));
        });
    }
    
    /**
     * 새로운 정책 생성
     * 
     * @param context 보안 컨텍스트
     * @param requirements 요구사항
     * @return 생성된 정책
     */
    public Mono<GeneratedPolicy> generatePolicy(
            Map<String, Object> context,
            List<String> requirements) {
        
        if (!evolutionEnabled) {
            return Mono.empty();
        }
        
        return Mono.defer(() -> {
            String policyId = generatePolicyId(context);
            
            // 유사한 정책 패턴 검색
            List<Document> similarPolicies = searchSimilarPolicies(context);
            
            // 정책 합성
            EvolvingPolicy newPolicy = synthesizeNewPolicy(
                policyId, context, requirements, similarPolicies
            );
            
            // 저장
            evolvingPolicies.put(policyId, newPolicy);
            savePolicyPattern(newPolicy);
            
            policiesGenerated.incrementAndGet();
            
            return Mono.just(new GeneratedPolicy(
                policyId,
                newPolicy.getRules(),
                newPolicy.getConfidence()
            ));
        });
    }
    
    /**
     * 진화된 임계값 조회
     * 
     * AI가 학습하여 동적으로 조정한 임계값을 반환합니다.
     * 
     * @param eventType 이벤트 타입
     * @return 진화된 임계값 맵
     */
    public Map<String, Double> getEvolvedThresholds(String eventType) {
        Map<String, Double> thresholds = new HashMap<>();
        
        // 기본 임계값
        thresholds.put("minimalThreshold", 0.8);
        thresholds.put("lowThreshold", 0.6);
        thresholds.put("mediumThreshold", 0.4);
        thresholds.put("highThreshold", 0.2);
        
        if (!evolutionEnabled) {
            return thresholds;
        }
        
        try {
            // 이벤트 타입별로 진화된 정책 검색
            String policyKey = "threshold_policy:" + eventType;
            EvolvingPolicy policy = evolvingPolicies.get(policyKey);
            
            if (policy != null && policy.getMetadata() != null) {
                // 진화된 임계값이 있으면 적용
                Map<String, Object> metadata = policy.getMetadata();
                
                if (metadata.containsKey("minimalThreshold")) {
                    thresholds.put("minimalThreshold", 
                        Double.parseDouble(metadata.get("minimalThreshold").toString()));
                }
                if (metadata.containsKey("lowThreshold")) {
                    thresholds.put("lowThreshold", 
                        Double.parseDouble(metadata.get("lowThreshold").toString()));
                }
                if (metadata.containsKey("mediumThreshold")) {
                    thresholds.put("mediumThreshold", 
                        Double.parseDouble(metadata.get("mediumThreshold").toString()));
                }
                if (metadata.containsKey("highThreshold")) {
                    thresholds.put("highThreshold", 
                        Double.parseDouble(metadata.get("highThreshold").toString()));
                }
                
                log.debug("Using evolved thresholds for {}: {}", eventType, thresholds);
            }
            
            // Vector Store에서 추가 학습 데이터 조회
            if (unifiedVectorService != null) {
                String query = "threshold evolution " + eventType;
                SearchRequest searchRequest = SearchRequest.builder()
                    .query(query)
                    .topK(1)
                    .similarityThreshold(0.8)
                    .build();

                List<Document> docs = unifiedVectorService.searchSimilar(searchRequest);
                if (!docs.isEmpty()) {
                    Document doc = docs.get(0);
                    Map<String, Object> learnedThresholds = doc.getMetadata();
                    
                    // 학습된 임계값 적용
                    for (String key : thresholds.keySet()) {
                        if (learnedThresholds.containsKey(key)) {
                            try {
                                double value = Double.parseDouble(
                                    learnedThresholds.get(key).toString());
                                thresholds.put(key, value);
                            } catch (NumberFormatException e) {
                                // 잘못된 값은 무시
                            }
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            log.error("Error getting evolved thresholds for {}", eventType, e);
        }
        
        return thresholds;
    }
    
    /**
     * 정책 효과성 평가
     * 
     * @param policyId 정책 ID
     * @return 효과성 점수 (0.0 ~ 1.0)
     */
    public double evaluatePolicyEffectiveness(String policyId) {
        PolicyEffectiveness metrics = effectivenessMetrics.get(policyId);
        if (metrics == null) {
            return 0.5; // 기본값
        }
        
        return metrics.calculateScore();
    }
    
    /**
     * 정책 추천
     * 
     * @param context 현재 보안 컨텍스트
     * @param topK 추천할 정책 수
     * @return 추천 정책 목록
     */
    public Flux<PolicyRecommendation> recommendPolicies(
            Map<String, Object> context, 
            int topK) {
        
        return Flux.defer(() -> {
            // 컨텍스트 기반 유사 정책 검색
            List<Document> candidates = searchSimilarPolicies(context);
            
            // 효과성 점수로 정렬
            return Flux.fromIterable(candidates)
                .map(doc -> {
                    String policyId = doc.getMetadata().get("policyId").toString();
                    double score = evaluatePolicyEffectiveness(policyId);
                    return new PolicyRecommendation(policyId, score, doc);
                })
                .sort(Comparator.comparingDouble(PolicyRecommendation::getScore).reversed())
                .take(topK);
        });
    }
    
    /**
     * 정책 효과성 업데이트
     */
    private void updatePolicyEffectiveness(String policyId, boolean outcome) {
        PolicyEffectiveness metrics = effectivenessMetrics.computeIfAbsent(
            policyId, k -> new PolicyEffectiveness()
        );
        
        if (outcome) {
            metrics.incrementSuccess();
        } else {
            metrics.incrementFailure();
        }
    }
    
    /**
     * 정책 진화 필요성 평가
     */
    private boolean shouldEvolvePolicy(String policyId) {
        PolicyEffectiveness metrics = effectivenessMetrics.get(policyId);
        if (metrics == null) {
            return false;
        }
        
        // 충분한 샘플이 있고 효과성이 임계값 이하일 때
        return metrics.getTotalSamples() >= minSamplesForEvolution &&
               metrics.calculateScore() < evolutionThreshold;
    }
    
    /**
     * 정책 파라미터 조정
     */
    private void adjustPolicyParameters(
            EvolvingPolicy policy,
            SecurityEvent event,
            String decision,
            boolean outcome) {
        
        // 간단한 강화학습 방식으로 파라미터 조정
        Map<String, Double> params = policy.getParameters();
        double learningRate = 0.1;
        
        for (Map.Entry<String, Double> entry : params.entrySet()) {
            double currentValue = entry.getValue();
            double adjustment = outcome ? learningRate : -learningRate;
            double newValue = Math.max(0.0, Math.min(1.0, currentValue + adjustment));
            entry.setValue(newValue);
        }
        
        policy.incrementVersion();
    }
    
    /**
     * 정책 규칙 합성
     */
    private void synthesizePolicyRules(EvolvingPolicy policy, SecurityEvent event) {
        // 이벤트 패턴에서 새로운 규칙 추출
        List<String> newRules = extractRulesFromEvent(event);
        
        // 기존 규칙과 병합
        Set<String> allRules = new HashSet<>(policy.getRules());
        allRules.addAll(newRules);
        
        // 중복 및 모순 제거
        allRules = resolveRuleConflicts(allRules);
        
        policy.setRules(new ArrayList<>(allRules));
    }
    
    /**
     * 유사 정책 검색
     */
    private List<Document> searchSimilarPolicies(Map<String, Object> context) {
        String query = buildQueryFromContext(context);
        
        SearchRequest request = SearchRequest.builder()
            .query(query)
            .topK(10)
            .similarityThreshold(0.7)
            .build();

        return unifiedVectorService.searchSimilar(request);
    }
    
    /**
     * Phase 2: 정책 패턴 저장 (Vector Store)
     *
     * 정책 진화 학습 결과를 vector_store에 저장하여 RAG 검색 시 활용
     */
    private void savePolicyPattern(EvolvingPolicy policy) {
        try {
            // 정책 패턴 텍스트 생성
            String content = String.format(
                "Policy Evolution: ID=%s, Version=%d, Rules=%s, Confidence=%.2f",
                policy.getId(),
                policy.getVersion(),
                policy.getRules(),
                policy.getConfidence()
            );

            Map<String, Object> metadata = new HashMap<>();

            // documentType 표준화 (Enum 사용)
            metadata.put("documentType", VectorDocumentType.POLICY_EVOLUTION.getValue());
            metadata.put("policyId", policy.getId());
            metadata.put("version", policy.getVersion());
            metadata.put("type", "evolving_policy");
            metadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            metadata.put("confidence", policy.getConfidence());

            // 정책 규칙 수
            metadata.put("ruleCount", policy.getRules().size());

            // 정책 파라미터
            if (policy.getParameters() != null && !policy.getParameters().isEmpty()) {
                metadata.put("parameters", policy.getParameters().toString());
            }

            // 정책 메타데이터
            if (policy.getMetadata() != null && !policy.getMetadata().isEmpty()) {
                for (Map.Entry<String, Object> entry : policy.getMetadata().entrySet()) {
                    metadata.put("policy_" + entry.getKey(), entry.getValue());
                }
            }

            Document doc = new Document(content, metadata);
            unifiedVectorService.storeDocument(doc);

            log.debug("[PolicyEvolution] 정책 패턴 저장 완료: policyId={}, version={}, confidence={}",
                policy.getId(), policy.getVersion(), policy.getConfidence());

        } catch (Exception e) {
            log.warn("[PolicyEvolution] 정책 패턴 저장 실패: policyId={}", policy.getId(), e);
        }
    }
    
    /**
     * 기존 정책 로드
     */
    private void loadExistingPolicies() {
        // 벡터 스토어에서 기존 정책 로드
        Map<String, Object> filterCriteria = Map.of("type", "evolving_policy");
        List<Document> existingPolicies = standardVectorStoreService.searchWithFilter(
            "policy", filterCriteria
        );
        
        for (Document doc : existingPolicies) {
            String policyId = doc.getMetadata().get("policyId").toString();
            // 정책 복원 로직
            log.debug("기존 정책 로드: {}", policyId);
        }
    }
    
    // Helper 메서드들
    private boolean isPositive(String outcome) {
        if (outcome == null) return false;
        String normalized = outcome.toUpperCase();
        return normalized.contains("SUCCESS") || normalized.contains("NORMAL") ||
               normalized.contains("LOW") || normalized.contains("PASS");
    }

    private String extractPolicyId(SecurityEvent event) {
        return "policy_" + event.getEventType() + "_" + event.getSeverity();
    }
    
    private String generatePolicyId(Map<String, Object> context) {
        return "policy_" + UUID.randomUUID().toString().substring(0, 8);
    }
    
    private void backupCurrentVersion(EvolvingPolicy policy) {
        List<PolicyVersion> history = policyVersionHistory.computeIfAbsent(
            policy.getId(), k -> new ArrayList<>()
        );
        history.add(policy.toVersion());
    }
    
    private List<String> extractRulesFromEvent(SecurityEvent event) {
        List<String> rules = new ArrayList<>();
        // 이벤트에서 규칙 추출 로직
        return rules;
    }
    
    private Set<String> resolveRuleConflicts(Set<String> rules) {
        // 규칙 충돌 해결 로직
        return rules;
    }
    
    private String buildQueryFromContext(Map<String, Object> context) {
        return context.toString(); // 간단한 구현
    }
    
    private EvolvingPolicy synthesizeNewPolicy(
            String policyId,
            Map<String, Object> context,
            List<String> requirements,
            List<Document> similarPolicies) {
        
        EvolvingPolicy policy = new EvolvingPolicy(policyId);
        // 정책 합성 로직
        return policy;
    }
    
    // 내부 클래스들
    
    /**
     * 진화하는 정책
     */
    private static class EvolvingPolicy {
        private final String id;
        private int version = 1;
        private List<String> rules = new ArrayList<>();
        private Map<String, Double> parameters = new HashMap<>();
        private Map<String, Object> metadata = new HashMap<>();
        private double confidence = 0.5;
        
        public EvolvingPolicy(String id) {
            this.id = id;
        }
        
        // Getters and setters
        public String getId() { return id; }
        public int getVersion() { return version; }
        public void incrementVersion() { this.version++; }
        public List<String> getRules() { return rules; }
        public void setRules(List<String> rules) { this.rules = rules; }
        public Map<String, Double> getParameters() { return parameters; }
        public Map<String, Object> getMetadata() { return metadata; }
        public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
        public double getConfidence() { return confidence; }
        
        public PolicyVersion toVersion() {
            return new PolicyVersion(version, new ArrayList<>(rules), new HashMap<>(parameters));
        }
    }
    
    /**
     * 정책 버전
     */
    private static class PolicyVersion {
        private final int version;
        private final List<String> rules;
        private final Map<String, Double> parameters;
        
        public PolicyVersion(int version, List<String> rules, Map<String, Double> parameters) {
            this.version = version;
            this.rules = rules;
            this.parameters = parameters;
        }
    }
    
    /**
     * 정책 효과성 메트릭
     */
    private static class PolicyEffectiveness {
        private long successCount = 0;
        private long failureCount = 0;
        
        public void incrementSuccess() { successCount++; }
        public void incrementFailure() { failureCount++; }
        
        public long getTotalSamples() {
            return successCount + failureCount;
        }
        
        public double calculateScore() {
            long total = getTotalSamples();
            if (total == 0) return 0.5;
            return (double) successCount / total;
        }
    }
    
    /**
     * 정책 학습 결과
     */
    public static class PolicyLearningResult {
        private final String status;
        private final String policyId;
        private final int version;
        
        private PolicyLearningResult(String status, String policyId, int version) {
            this.status = status;
            this.policyId = policyId;
            this.version = version;
        }
        
        public static PolicyLearningResult disabled() {
            return new PolicyLearningResult("disabled", null, 0);
        }
        
        public static PolicyLearningResult recorded(String policyId) {
            return new PolicyLearningResult("recorded", policyId, 0);
        }
        
        public static PolicyLearningResult evolved(String policyId, int version) {
            return new PolicyLearningResult("evolved", policyId, version);
        }
        
        // Getters
        public String getStatus() { return status; }
        public String getPolicyId() { return policyId; }
        public int getVersion() { return version; }
    }
    
    /**
     * 생성된 정책
     */
    public static class GeneratedPolicy {
        private final String id;
        private final List<String> rules;
        private final double confidence;
        
        public GeneratedPolicy(String id, List<String> rules, double confidence) {
            this.id = id;
            this.rules = rules;
            this.confidence = confidence;
        }
        
        // Getters
        public String getId() { return id; }
        public List<String> getRules() { return rules; }
        public double getConfidence() { return confidence; }
    }
    
    /**
     * 정책 추천
     */
    public static class PolicyRecommendation {
        private final String policyId;
        private final double score;
        private final Document document;
        
        public PolicyRecommendation(String policyId, double score, Document document) {
            this.policyId = policyId;
            this.score = score;
            this.document = document;
        }
        
        // Getters
        public String getPolicyId() { return policyId; }
        public double getScore() { return score; }
        public Document getDocument() { return document; }
    }
}