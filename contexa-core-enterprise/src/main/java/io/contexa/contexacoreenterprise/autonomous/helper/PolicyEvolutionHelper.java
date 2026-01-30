package io.contexa.contexacoreenterprise.autonomous.helper;

import io.contexa.contexacore.autonomous.PolicyEvolutionService;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacoreenterprise.autonomous.intelligence.AITuningService;
import io.contexa.contexacore.domain.VectorDocumentType;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@RequiredArgsConstructor
public class PolicyEvolutionHelper implements PolicyEvolutionService {

    private final UnifiedVectorService unifiedVectorService;

    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;

    @Value("${policy.evolution.enabled:true}")
    private boolean evolutionEnabled;
    
    @Value("${policy.evolution.threshold:0.75}")
    private double evolutionThreshold;
    
    @Value("${policy.evolution.min-samples:10}")
    private int minSamplesForEvolution;
    
    @Value("${policy.evolution.retention-days:90}")
    private int policyRetentionDays;

    private final Map<String, EvolvingPolicy> evolvingPolicies = new ConcurrentHashMap<>();

    private final Map<String, List<PolicyVersion>> policyVersionHistory = new ConcurrentHashMap<>();

    private final Map<String, PolicyEffectiveness> effectivenessMetrics = new ConcurrentHashMap<>();

    private final AtomicLong totalEvolutions = new AtomicLong(0);
    private final AtomicLong successfulEvolutions = new AtomicLong(0);
    private final AtomicLong policiesGenerated = new AtomicLong(0);
    
    @PostConstruct
    public void initialize() {
        if (!evolutionEnabled) {
                        return;
        }

        loadExistingPolicies();
        
            }

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

            boolean result = isPositive(outcome);

            updatePolicyEffectiveness(policyId, result);

            if (shouldEvolvePolicy(policyId)) {
                return evolvePolicy(policyId, event, decision, result);
            }

            return Mono.just(PolicyLearningResult.recorded(policyId));
        });
    }

    @Override
    public void evolvePolicy(SecurityEvent event, ThreatAssessment assessment) {
        
        if (event != null) {
            String policyId = "POLICY_" + event.getSeverity();
            recordPolicyApplication(policyId, event, "AUTO", true);
        }
    }

    private void recordPolicyApplication(String policyId, SecurityEvent event, String applicationType, boolean success) {
        try {
            Map<String, Object> applicationRecord = new HashMap<>();
            applicationRecord.put("policyId", policyId);
            applicationRecord.put("eventId", event.getEventId());
            
            applicationRecord.put("severity", event.getSeverity() != null ? event.getSeverity().name() : "UNKNOWN");
            applicationRecord.put("applicationType", applicationType);
            applicationRecord.put("success", success);
            applicationRecord.put("timestamp", System.currentTimeMillis());

            String key = "policy:applications:" + policyId;
            redisTemplate.opsForList().rightPush(key, applicationRecord);

            redisTemplate.expire(key, Duration.ofDays(30));

                    } catch (Exception e) {
            log.error("Failed to record policy application: {}", policyId, e);
        }
    }

    private Mono<PolicyLearningResult> evolvePolicy(
            String policyId,
            SecurityEvent event,
            String decision,
            boolean outcome) {
        
        return Mono.defer(() -> {
            EvolvingPolicy policy = evolvingPolicies.computeIfAbsent(
                policyId, k -> new EvolvingPolicy(k)
            );

            backupCurrentVersion(policy);

            adjustPolicyParameters(policy, event, decision, outcome);

            synthesizePolicyRules(policy, event);

            savePolicyPattern(policy);

            totalEvolutions.incrementAndGet();
            if (outcome) {
                successfulEvolutions.incrementAndGet();
            }

            return Mono.just(PolicyLearningResult.evolved(policyId, policy.getVersion()));
        });
    }

    public Mono<GeneratedPolicy> generatePolicy(
            Map<String, Object> context,
            List<String> requirements) {
        
        if (!evolutionEnabled) {
            return Mono.empty();
        }
        
        return Mono.defer(() -> {
            String policyId = generatePolicyId(context);

            List<Document> similarPolicies = searchSimilarPolicies(context);

            EvolvingPolicy newPolicy = synthesizeNewPolicy(
                policyId, context, requirements, similarPolicies
            );

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

    public Map<String, Double> getEvolvedThresholds(String eventType) {
        Map<String, Double> thresholds = new HashMap<>();

        thresholds.put("minimalThreshold", 0.8);
        thresholds.put("lowThreshold", 0.6);
        thresholds.put("mediumThreshold", 0.4);
        thresholds.put("highThreshold", 0.2);
        
        if (!evolutionEnabled) {
            return thresholds;
        }
        
        try {
            
            String policyKey = "threshold_policy:" + eventType;
            EvolvingPolicy policy = evolvingPolicies.get(policyKey);
            
            if (policy != null && policy.getMetadata() != null) {
                
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
                
                            }

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

                    for (String key : thresholds.keySet()) {
                        if (learnedThresholds.containsKey(key)) {
                            try {
                                double value = Double.parseDouble(
                                    learnedThresholds.get(key).toString());
                                thresholds.put(key, value);
                            } catch (NumberFormatException e) {
                                
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

    public double evaluatePolicyEffectiveness(String policyId) {
        PolicyEffectiveness metrics = effectivenessMetrics.get(policyId);
        if (metrics == null) {
            return 0.5; 
        }
        
        return metrics.calculateScore();
    }

    public Flux<PolicyRecommendation> recommendPolicies(
            Map<String, Object> context, 
            int topK) {
        
        return Flux.defer(() -> {
            
            List<Document> candidates = searchSimilarPolicies(context);

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

    private boolean shouldEvolvePolicy(String policyId) {
        PolicyEffectiveness metrics = effectivenessMetrics.get(policyId);
        if (metrics == null) {
            return false;
        }

        return metrics.getTotalSamples() >= minSamplesForEvolution &&
               metrics.calculateScore() < evolutionThreshold;
    }

    private void adjustPolicyParameters(
            EvolvingPolicy policy,
            SecurityEvent event,
            String decision,
            boolean outcome) {

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

    private void synthesizePolicyRules(EvolvingPolicy policy, SecurityEvent event) {
        
        List<String> newRules = extractRulesFromEvent(event);

        Set<String> allRules = new HashSet<>(policy.getRules());
        allRules.addAll(newRules);

        allRules = resolveRuleConflicts(allRules);
        
        policy.setRules(new ArrayList<>(allRules));
    }

    private List<Document> searchSimilarPolicies(Map<String, Object> context) {
        String query = buildQueryFromContext(context);
        
        SearchRequest request = SearchRequest.builder()
            .query(query)
            .topK(10)
            .similarityThreshold(0.7)
            .build();

        return unifiedVectorService.searchSimilar(request);
    }

    private void savePolicyPattern(EvolvingPolicy policy) {
        try {
            
            String content = String.format(
                "Policy Evolution: ID=%s, Version=%d, Rules=%s, Confidence=%.2f",
                policy.getId(),
                policy.getVersion(),
                policy.getRules(),
                policy.getConfidence()
            );

            Map<String, Object> metadata = new HashMap<>();

            metadata.put("documentType", VectorDocumentType.POLICY_EVOLUTION.getValue());
            metadata.put("policyId", policy.getId());
            metadata.put("version", policy.getVersion());
            metadata.put("type", "evolving_policy");
            metadata.put("timestamp", LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            metadata.put("confidence", policy.getConfidence());

            metadata.put("ruleCount", policy.getRules().size());

            if (policy.getParameters() != null && !policy.getParameters().isEmpty()) {
                metadata.put("parameters", policy.getParameters().toString());
            }

            if (policy.getMetadata() != null && !policy.getMetadata().isEmpty()) {
                for (Map.Entry<String, Object> entry : policy.getMetadata().entrySet()) {
                    metadata.put("policy_" + entry.getKey(), entry.getValue());
                }
            }

            Document doc = new Document(content, metadata);
            unifiedVectorService.storeDocument(doc);

        } catch (Exception e) {
            log.warn("[PolicyEvolution] 정책 패턴 저장 실패: policyId={}", policy.getId(), e);
        }
    }

    private void loadExistingPolicies() {
        try {
            FilterExpressionBuilder builder = new FilterExpressionBuilder();
            Filter.Expression filter = builder.eq("type", "evolving_policy").build();

            SearchRequest searchRequest = SearchRequest.builder()
                .query("policy")
                .topK(100)
                .similarityThreshold(0.5)
                .filterExpression(filter)
                .build();

            List<Document> existingPolicies = unifiedVectorService.searchSimilar(searchRequest);

            for (Document doc : existingPolicies) {
                if (doc.getMetadata().containsKey("policyId")) {
                    String policyId = doc.getMetadata().get("policyId").toString();
                }
            }
        } catch (Exception e) {
            log.warn("[PolicyEvolutionHelper] Failed to load existing policies", e);
        }
    }

    private boolean isPositive(String outcome) {
        if (outcome == null) return false;
        String normalized = outcome.toUpperCase();
        return normalized.contains("SUCCESS") || normalized.contains("NORMAL") ||
               normalized.contains("LOW") || normalized.contains("PASS");
    }

    private String extractPolicyId(SecurityEvent event) {
        return "policy_" + event.getSeverity() + "_" + event.getSource();
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
        
        return rules;
    }
    
    private Set<String> resolveRuleConflicts(Set<String> rules) {
        
        return rules;
    }
    
    private String buildQueryFromContext(Map<String, Object> context) {
        return context.toString(); 
    }
    
    private EvolvingPolicy synthesizeNewPolicy(
            String policyId,
            Map<String, Object> context,
            List<String> requirements,
            List<Document> similarPolicies) {
        
        EvolvingPolicy policy = new EvolvingPolicy(policyId);
        
        return policy;
    }

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

        public String getStatus() { return status; }
        public String getPolicyId() { return policyId; }
        public int getVersion() { return version; }
    }

    public static class GeneratedPolicy {
        private final String id;
        private final List<String> rules;
        private final double confidence;
        
        public GeneratedPolicy(String id, List<String> rules, double confidence) {
            this.id = id;
            this.rules = rules;
            this.confidence = confidence;
        }

        public String getId() { return id; }
        public List<String> getRules() { return rules; }
        public double getConfidence() { return confidence; }
    }

    public static class PolicyRecommendation {
        private final String policyId;
        private final double score;
        private final Document document;
        
        public PolicyRecommendation(String policyId, double score, Document document) {
            this.policyId = policyId;
            this.score = score;
            this.document = document;
        }

        public String getPolicyId() { return policyId; }
        public double getScore() { return score; }
        public Document getDocument() { return document; }
    }
}