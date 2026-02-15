package io.contexa.contexacoreenterprise.autonomous.labs;

import io.contexa.contexacore.std.labs.AbstractAILab;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class PolicyEvolutionLab extends AbstractAILab<PolicyEvolutionLab.PolicyEvolutionRequest, PolicyEvolutionLab.PolicyEvolutionResponse> {

    private final ChatModel chatModel;
    private final UnifiedVectorService unifiedVectorService;
    private final RedisTemplate<String, Object> redisTemplate;

    private final Map<String, CachedPolicy> policyCache = new ConcurrentHashMap<>();

    @Autowired
    public PolicyEvolutionLab(
            ChatModel chatModel,
            UnifiedVectorService unifiedVectorService,
            RedisTemplate<String, Object> redisTemplate) {

        super("PolicyEvolutionLab");
        this.chatModel = chatModel;
        this.unifiedVectorService = unifiedVectorService;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected PolicyEvolutionResponse doProcess(PolicyEvolutionRequest request) throws Exception {

        AnalysisResult analysis = analyzeContext(request);

        List<ExistingPolicy> existingPolicies = searchExistingPolicies(request, analysis);

        EvolvedPolicy evolvedPolicy = evolveOrGeneratePolicy(request, analysis, existingPolicies);

        double effectiveness = evaluatePolicyEffectiveness(evolvedPolicy, request);

        storeInMemory(evolvedPolicy, effectiveness);

        return buildResponse(evolvedPolicy, effectiveness, analysis);
    }

    @Override
    protected Mono<PolicyEvolutionResponse> doProcessAsync(PolicyEvolutionRequest request) {
        return Mono.fromCallable(() -> {

            AnalysisResult analysis = analyzeContext(request);

            return searchExistingPoliciesAsync(request, analysis)
            .flatMap(existingPolicies -> {

                return evolveOrGeneratePolicyAsync(request, analysis, existingPolicies);
            })
            .flatMap(evolvedPolicy -> {

                double effectiveness = evaluatePolicyEffectiveness(evolvedPolicy, request);

                return storeInMemoryAsync(evolvedPolicy, effectiveness)
                    .thenReturn(buildResponse(evolvedPolicy, effectiveness, analysis));
            });
        })
        .flatMap(mono -> mono)
                .doOnError(error -> log.error("Async policy evolution failed", error));
    }

    @Override
    protected Flux<String> doProcessStream(PolicyEvolutionRequest request) {

        return Flux.create(sink -> {
            try {

                sink.next("Analyzing context...\n");
                AnalysisResult analysis = analyzeContext(request);
                sink.next("Context analysis complete: " + analysis.getSummary() + "\n\n");

                sink.next("Searching existing policies...\n");
                List<ExistingPolicy> existingPolicies = searchExistingPolicies(request, analysis);
                sink.next("Found " + existingPolicies.size() + " related policies\n\n");

                sink.next("Starting policy evolution...\n");

                String prompt = buildEvolutionPrompt(request, analysis, existingPolicies);
                Prompt aiPrompt = new Prompt(prompt);

                chatModel.stream(aiPrompt)
                    .doOnNext(response -> {
                        String content = response.getResult().getOutput().getText();
                        if (content != null && !content.isEmpty()) {
                            sink.next(content);
                        }
                    })
                    .doOnComplete(() -> {
                        sink.next("\n\nPolicy evolution complete\n");
                        sink.complete();
                    })
                    .doOnError(sink::error)
                    .subscribe();

            } catch (Exception e) {
                sink.error(e);
            }
        });
    }

    @Override
    protected void validateRequest(PolicyEvolutionRequest request) {
        super.validateRequest(request);

        if (request.getContext() == null || request.getContext().isEmpty()) {
            throw new IllegalArgumentException("Policy context is empty");
        }

        if (request.getEvolutionMode() == null) {
            request.setEvolutionMode(EvolutionMode.ADAPTIVE);
        }
    }

    private AnalysisResult analyzeContext(PolicyEvolutionRequest request) {
        AnalysisResult result = new AnalysisResult();

        Map<String, Object> context = request.getContext();
        result.setThreatLevel(extractFromContext(context, "threatLevel", "MEDIUM"));
        result.setDomain(extractFromContext(context, "domain", "GENERAL"));
        result.setRequirements(extractRequirements(request));

        result.setSummary(String.format("ThreatLevel: %s, Domain: %s, Requirements: %d",
            result.getThreatLevel(), result.getDomain(), result.getRequirements().size()));

        return result;
    }

    private String extractFromContext(Map<String, Object> context, String key, String defaultValue) {
        Object value = context.get(key);
        return value != null ? value.toString() : defaultValue;
    }

    private List<ExistingPolicy> searchExistingPolicies(
            PolicyEvolutionRequest request,
            AnalysisResult analysis) {

        String cacheKey = generateCacheKey(request);
        CachedPolicy cached = policyCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            return cached.getPolicies();
        }

        List<ExistingPolicy> policies = new ArrayList<>();

        try {
            String query = request.getContext().toString();
            SearchRequest searchRequest = SearchRequest.builder()
                .query(query)
                .topK(5)
                .similarityThreshold(0.7)
                .build();

            List<Document> documents = unifiedVectorService.searchSimilar(searchRequest);
            for (Document doc : documents) {
                String policyId = doc.getMetadata().getOrDefault("policyId", doc.getId()).toString();
                policies.add(new ExistingPolicy(policyId, 1.0, doc.getText()));
            }
        } catch (Exception e) {
            log.error("Failed to search existing policies", e);
        }

        policyCache.put(cacheKey, new CachedPolicy(policies));

        return policies;
    }

    private EvolvedPolicy evolveOrGeneratePolicy(
            PolicyEvolutionRequest request,
            AnalysisResult analysis,
            List<ExistingPolicy> existingPolicies) throws Exception {

        if (!existingPolicies.isEmpty() && request.getEvolutionMode() == EvolutionMode.ADAPTIVE) {
            return evolveExistingPolicy(existingPolicies.get(0), request, analysis);
        } else {
            return generateNewPolicy(request, analysis);
        }
    }

    private EvolvedPolicy evolveExistingPolicy(
            ExistingPolicy basePolicy,
            PolicyEvolutionRequest request,
            AnalysisResult analysis) throws Exception {

        String prompt = buildEvolutionPrompt(request, analysis, List.of(basePolicy));
        ChatResponse response = chatModel.call(new Prompt(prompt));

        EvolvedPolicy evolved = new EvolvedPolicy();
        evolved.setPolicyId(UUID.randomUUID().toString());
        evolved.setBasePolicy(basePolicy.getId());
        evolved.setContent(response.getResult().getOutput().getText());
        evolved.setVersion(basePolicy.getScore() > 0.8 ? 2 : 1);
        evolved.setEvolutionType("ADAPTIVE");

        return evolved;
    }

    private EvolvedPolicy generateNewPolicy(
            PolicyEvolutionRequest request,
            AnalysisResult analysis) throws Exception {

        String prompt = buildEvolutionPrompt(request, analysis, Collections.emptyList());
        ChatResponse response = chatModel.call(new Prompt(prompt));

        EvolvedPolicy policy = new EvolvedPolicy();
        policy.setPolicyId(UUID.randomUUID().toString());
        policy.setContent(response.getResult().getOutput().getText());
        policy.setConfidence(0.7);
        policy.setVersion(1);
        policy.setEvolutionType("GENERATED");

        return policy;
    }

    private double evaluatePolicyEffectiveness(EvolvedPolicy policy, PolicyEvolutionRequest request) {
        double baseScore = policy.getConfidence();

        List<String> requirements = request.getRequirements();
        if (requirements == null || requirements.isEmpty() || policy.getContent() == null) {
            return baseScore;
        }

        long matchCount = requirements.stream()
            .filter(req -> policy.getContent().toLowerCase().contains(req.toLowerCase()))
            .count();
        double contextScore = (double) matchCount / requirements.size();

        return (baseScore + contextScore) / 2.0;
    }

    private void storeInMemory(EvolvedPolicy policy, double effectiveness) {

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("policyId", policy.getPolicyId());
        metadata.put("effectiveness", effectiveness);
        metadata.put("version", policy.getVersion());
        metadata.put("type", policy.getEvolutionType());

        try {
            // Short-term cache in Redis
            String stmKey = "policy:stm:" + policy.getPolicyId();
            redisTemplate.opsForValue().set(stmKey, metadata, Duration.ofMinutes(30));

            // Long-term storage in vector store for high-effectiveness policies
            if (effectiveness > 0.8 && policy.getContent() != null) {
                Map<String, Object> docMetadata = new HashMap<>(metadata);
                docMetadata.put("documentType", "POLICY_EVOLUTION");
                Document doc = new Document(policy.getContent(), docMetadata);
                unifiedVectorService.storeDocument(doc);
            }
        } catch (Exception e) {
            log.error("Failed to store policy in memory: policyId={}", policy.getPolicyId(), e);
        }
    }

    private Mono<Void> storeInMemoryAsync(EvolvedPolicy policy, double effectiveness) {
        return Mono.fromRunnable(() -> storeInMemory(policy, effectiveness));
    }

    private PolicyEvolutionResponse buildResponse(
            EvolvedPolicy policy,
            double effectiveness,
            AnalysisResult analysis) {

        PolicyEvolutionResponse response = new PolicyEvolutionResponse();
        response.setPolicyId(policy.getPolicyId());
        response.setPolicyContent(policy.getContent());
        response.setEffectiveness(effectiveness);
        response.setVersion(policy.getVersion());
        response.setEvolutionType(policy.getEvolutionType());
        response.setAnalysis(analysis);
        response.setTimestamp(new Date());

        return response;
    }

    private Mono<List<ExistingPolicy>> searchExistingPoliciesAsync(
            PolicyEvolutionRequest request,
            AnalysisResult analysis) {

        return Mono.fromCallable(() -> searchExistingPolicies(request, analysis));
    }

    private Mono<EvolvedPolicy> evolveOrGeneratePolicyAsync(
            PolicyEvolutionRequest request,
            AnalysisResult analysis,
            List<ExistingPolicy> existingPolicies) {

        return Mono.fromCallable(() -> evolveOrGeneratePolicy(request, analysis, existingPolicies));
    }

    private String buildEvolutionPrompt(
            PolicyEvolutionRequest request,
            AnalysisResult analysis,
            List<ExistingPolicy> existingPolicies) {

        StringBuilder prompt = new StringBuilder();
        prompt.append("다음 컨텍스트에 대한 보안 정책을 생성하거나 개선하세요:\n\n");
        prompt.append("컨텍스트:\n").append(request.getContext()).append("\n\n");
        prompt.append("분석 결과:\n").append(analysis.getSummary()).append("\n\n");

        if (!existingPolicies.isEmpty()) {
            prompt.append("참고할 기존 정책:\n");
            existingPolicies.forEach(p ->
                prompt.append("- ").append(p.getContent()).append("\n")
            );
            prompt.append("\n");
        }

        prompt.append("요구사항:\n");
        analysis.getRequirements().forEach(req ->
            prompt.append("- ").append(req).append("\n")
        );

        prompt.append("\n정책을 YAML 형식으로 생성하세요.");

        return prompt.toString();
    }

    private List<String> extractRequirements(PolicyEvolutionRequest request) {
        return request.getRequirements() != null ?
            request.getRequirements() : Collections.emptyList();
    }

    private String generateCacheKey(PolicyEvolutionRequest request) {
        return "policy_cache_" + request.getContext().hashCode();
    }

    public static class PolicyEvolutionRequest {
        private Map<String, Object> context;
        private List<String> requirements;
        private EvolutionMode evolutionMode;
        private Map<String, Object> additionalParams;

        public Map<String, Object> getContext() { return context; }
        public void setContext(Map<String, Object> context) { this.context = context; }
        public List<String> getRequirements() { return requirements; }
        public void setRequirements(List<String> requirements) { this.requirements = requirements; }
        public EvolutionMode getEvolutionMode() { return evolutionMode; }
        public void setEvolutionMode(EvolutionMode mode) { this.evolutionMode = mode; }
        public Map<String, Object> getAdditionalParams() { return additionalParams; }
        public void setAdditionalParams(Map<String, Object> params) { this.additionalParams = params; }
    }

    public static class PolicyEvolutionResponse {
        private String policyId;
        private String policyContent;
        private double effectiveness;
        private int version;
        private String evolutionType;
        private AnalysisResult analysis;
        private Date timestamp;

        public String getPolicyId() { return policyId; }
        public void setPolicyId(String policyId) { this.policyId = policyId; }
        public String getPolicyContent() { return policyContent; }
        public void setPolicyContent(String content) { this.policyContent = content; }
        public double getEffectiveness() { return effectiveness; }
        public void setEffectiveness(double effectiveness) { this.effectiveness = effectiveness; }
        public int getVersion() { return version; }
        public void setVersion(int version) { this.version = version; }
        public String getEvolutionType() { return evolutionType; }
        public void setEvolutionType(String type) { this.evolutionType = type; }
        public AnalysisResult getAnalysis() { return analysis; }
        public void setAnalysis(AnalysisResult analysis) { this.analysis = analysis; }
        public Date getTimestamp() { return timestamp; }
        public void setTimestamp(Date timestamp) { this.timestamp = timestamp; }
    }

    public enum EvolutionMode {
        ADAPTIVE,
        GENERATIVE,
        HYBRID
    }

    private static class AnalysisResult {
        private String threatLevel;
        private String domain;
        private List<String> requirements;
        private String summary;

        public String getThreatLevel() { return threatLevel; }
        public void setThreatLevel(String level) { this.threatLevel = level; }
        public String getDomain() { return domain; }
        public void setDomain(String domain) { this.domain = domain; }
        public List<String> getRequirements() { return requirements; }
        public void setRequirements(List<String> requirements) { this.requirements = requirements; }
        public String getSummary() { return summary; }
        public void setSummary(String summary) { this.summary = summary; }
    }

    private static class ExistingPolicy {
        private final String id;
        private final double score;
        private final String content;

        public ExistingPolicy(String id, double score, String content) {
            this.id = id;
            this.score = score;
            this.content = content;
        }

        public String getId() { return id; }
        public double getScore() { return score; }
        public String getContent() { return content; }
    }

    private static class EvolvedPolicy {
        private String policyId;
        private String basePolicy;
        private String content;
        private double confidence = 0.5;
        private int version = 1;
        private String evolutionType;

        public String getPolicyId() { return policyId; }
        public void setPolicyId(String id) { this.policyId = id; }
        public String getBasePolicy() { return basePolicy; }
        public void setBasePolicy(String base) { this.basePolicy = base; }
        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
        public int getVersion() { return version; }
        public void setVersion(int version) { this.version = version; }
        public String getEvolutionType() { return evolutionType; }
        public void setEvolutionType(String type) { this.evolutionType = type; }
    }

    private static class CachedPolicy {
        private final List<ExistingPolicy> policies;
        private final long timestamp;
        private static final long CACHE_TTL = 300000;

        public CachedPolicy(List<ExistingPolicy> policies) {
            this.policies = policies;
            this.timestamp = System.currentTimeMillis();
        }

        public boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_TTL;
        }

        public List<ExistingPolicy> getPolicies() { return policies; }
    }
}
