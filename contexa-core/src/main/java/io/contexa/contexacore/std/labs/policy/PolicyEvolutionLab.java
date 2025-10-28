package io.contexa.contexacore.std.labs.policy;

import io.opentelemetry.api.trace.Tracer;
import io.contexa.contexacore.std.labs.AbstractAILab;
import io.contexa.contexacore.autonomous.helper.PolicyEvolutionHelper;
import io.contexa.contexacore.autonomous.helper.LearningEngineHelper;
import io.contexa.contexacore.autonomous.helper.MemorySystemHelper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PolicyEvolutionLab - 자율 진화형 정책 연구실
 * 
 * 보안 정책의 자율적 진화와 합성을 담당하는 AI Lab입니다.
 * AbstractAILab을 상속받아 표준 파이프라인 패턴을 따릅니다.
 * 
 * 주요 기능:
 * - 정책 패턴 학습 및 진화
 * - 동적 정책 생성 및 최적화
 * - 정책 효과성 평가 및 개선
 * - 메모리 기반 정책 추천
 * 
 * @since 1.0.0
 */
@Slf4j
@Component
public class PolicyEvolutionLab extends AbstractAILab<PolicyEvolutionLab.PolicyEvolutionRequest, PolicyEvolutionLab.PolicyEvolutionResponse> {
    
    private final ChatModel chatModel;
    private final PolicyEvolutionHelper policyEvolutionHelper;
    private final LearningEngineHelper learningEngineHelper;
    private final MemorySystemHelper memorySystemHelper;
    
    // 정책 캐시
    private final Map<String, CachedPolicy> policyCache = new ConcurrentHashMap<>();
    
    @Autowired
    public PolicyEvolutionLab(
            Tracer tracer,
            ChatModel chatModel,
            PolicyEvolutionHelper policyEvolutionHelper,
            LearningEngineHelper learningEngineHelper,
            MemorySystemHelper memorySystemHelper) {

        super("PolicyEvolutionLab", tracer);
        this.chatModel = chatModel;
        this.policyEvolutionHelper = policyEvolutionHelper;
        this.learningEngineHelper = learningEngineHelper;
        this.memorySystemHelper = memorySystemHelper;
        
        log.info("PolicyEvolutionLab 초기화 완료");
    }
    
    /**
     * 스트리밍 지원 여부
     */
    @Override
    public boolean supportsStreaming() {
        return true;
    }
    
    /**
     * 동기 처리 구현
     * AbstractAILab의 Template Method 패턴 구현
     */
    @Override
    protected PolicyEvolutionResponse doProcess(PolicyEvolutionRequest request) throws Exception {
        log.info("정책 진화 처리 시작: {}", request.getContext());
        
        // 1. 컨텍스트 분석
        AnalysisResult analysis = analyzeContext(request);
        
        // 2. 기존 정책 검색
        List<ExistingPolicy> existingPolicies = searchExistingPolicies(request, analysis);
        
        // 3. 정책 진화/생성
        EvolvedPolicy evolvedPolicy = evolveOrGeneratePolicy(request, analysis, existingPolicies);
        
        // 4. 효과성 평가
        double effectiveness = evaluatePolicyEffectiveness(evolvedPolicy, request);
        
        // 5. 메모리 저장
        storeInMemory(evolvedPolicy, effectiveness);
        
        // 6. 응답 생성
        return buildResponse(evolvedPolicy, effectiveness, analysis);
    }
    
    /**
     * 비동기 처리 구현
     */
    @Override
    protected Mono<PolicyEvolutionResponse> doProcessAsync(PolicyEvolutionRequest request) {
        return Mono.fromCallable(() -> {
            log.info("비동기 정책 진화 처리 시작");
            
            // 컨텍스트 분석
            AnalysisResult analysis = analyzeContext(request);
            
            // 병렬 처리: 기존 정책 검색 + 학습 데이터 조회
            return Mono.zip(
                searchExistingPoliciesAsync(request, analysis),
                retrieveLearningDataAsync(request)
            )
            .flatMap(tuple -> {
                List<ExistingPolicy> existingPolicies = tuple.getT1();
                LearningData learningData = tuple.getT2();
                
                // 정책 진화
                return evolveOrGeneratePolicyAsync(request, analysis, existingPolicies, learningData);
            })
            .flatMap(evolvedPolicy -> {
                // 효과성 평가
                double effectiveness = evaluatePolicyEffectiveness(evolvedPolicy, request);
                
                // 메모리 저장 (비동기)
                return storeInMemoryAsync(evolvedPolicy, effectiveness)
                    .thenReturn(buildResponse(evolvedPolicy, effectiveness, analysis));
            });
        })
        .flatMap(mono -> mono)
        .doOnSuccess(response -> log.info("비동기 정책 진화 완료"))
        .doOnError(error -> log.error("비동기 정책 진화 실패", error));
    }
    
    /**
     * 스트리밍 처리 구현
     */
    @Override
    protected Flux<String> doProcessStream(PolicyEvolutionRequest request) {
        log.info("스트리밍 정책 진화 시작");
        
        return Flux.create(sink -> {
            try {
                // 1. 초기 분석 스트리밍
                sink.next("컨텍스트 분석 중...\n");
                AnalysisResult analysis = analyzeContext(request);
                sink.next("컨텍스트 분석 완료: " + analysis.getSummary() + "\n\n");
                
                // 2. 기존 정책 검색 스트리밍
                sink.next("🔎 기존 정책 검색 중...\n");
                List<ExistingPolicy> existingPolicies = searchExistingPolicies(request, analysis);
                sink.next("" + existingPolicies.size() + "개의 관련 정책 발견\n\n");
                
                // 3. 정책 진화 과정 스트리밍
                sink.next("정책 진화 시작...\n");
                
                // LLM을 통한 정책 생성 (스트리밍)
                String prompt = buildEvolutionPrompt(request, analysis, existingPolicies);
                Prompt aiPrompt = new Prompt(prompt);
                
                // ChatModel의 스트리밍 응답 처리
                chatModel.stream(aiPrompt)
                    .doOnNext(response -> {
                        String content = response.getResult().getOutput().getText();
                        if (content != null && !content.isEmpty()) {
                            sink.next(content);
                        }
                    })
                    .doOnComplete(() -> {
                        sink.next("\n\n정책 진화 완료\n");
                        sink.complete();
                    })
                    .doOnError(sink::error)
                    .subscribe();
                    
            } catch (Exception e) {
                sink.error(e);
            }
        });
    }
    
    /**
     * 요청 검증 (오버라이드)
     */
    @Override
    protected void validateRequest(PolicyEvolutionRequest request) {
        super.validateRequest(request);
        
        if (request.getContext() == null || request.getContext().isEmpty()) {
            throw new IllegalArgumentException("정책 컨텍스트가 비어있습니다");
        }
        
        if (request.getEvolutionMode() == null) {
            request.setEvolutionMode(EvolutionMode.ADAPTIVE);
        }
    }
    
    // ==================== Private 메서드들 ====================
    
    /**
     * 컨텍스트 분석
     */
    private AnalysisResult analyzeContext(PolicyEvolutionRequest request) {
        AnalysisResult result = new AnalysisResult();
        
        // 위협 레벨 분석
        result.setThreatLevel(analyzeThreatLevel(request.getContext()));
        
        // 도메인 식별
        result.setDomain(identifyDomain(request.getContext()));
        
        // 요구사항 추출
        result.setRequirements(extractRequirements(request));
        
        // 요약 생성
        result.setSummary(String.format("위협레벨: %s, 도메인: %s, 요구사항: %d개",
            result.getThreatLevel(), result.getDomain(), result.getRequirements().size()));
        
        return result;
    }
    
    /**
     * 기존 정책 검색
     */
    private List<ExistingPolicy> searchExistingPolicies(
            PolicyEvolutionRequest request, 
            AnalysisResult analysis) {
        
        // 캐시 확인
        String cacheKey = generateCacheKey(request);
        CachedPolicy cached = policyCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            return cached.getPolicies();
        }
        
        // Helper를 통한 정책 검색
        List<ExistingPolicy> policies = new ArrayList<>();
        
        policyEvolutionHelper.recommendPolicies(request.getContext(), 5)
            .collectList()
            .block()
            .forEach(recommendation -> {
                policies.add(new ExistingPolicy(
                    recommendation.getPolicyId(),
                    recommendation.getScore(),
                    recommendation.getDocument().getText()
                ));
            });
        
        // 캐시 저장
        policyCache.put(cacheKey, new CachedPolicy(policies));
        
        return policies;
    }
    
    /**
     * 정책 진화 또는 생성
     */
    private EvolvedPolicy evolveOrGeneratePolicy(
            PolicyEvolutionRequest request,
            AnalysisResult analysis,
            List<ExistingPolicy> existingPolicies) throws Exception {
        
        EvolvedPolicy policy = new EvolvedPolicy();
        
        if (!existingPolicies.isEmpty() && request.getEvolutionMode() == EvolutionMode.ADAPTIVE) {
            // 기존 정책 진화
            policy = evolveExistingPolicy(existingPolicies.get(0), request, analysis);
        } else {
            // 새 정책 생성
            policy = generateNewPolicy(request, analysis);
        }
        
        // 학습 엔진에 패턴 등록
        registerPatternToLearningEngine(policy);
        
        return policy;
    }
    
    /**
     * 기존 정책 진화
     */
    private EvolvedPolicy evolveExistingPolicy(
            ExistingPolicy basePolicy,
            PolicyEvolutionRequest request,
            AnalysisResult analysis) throws Exception {
        
        // LLM을 통한 정책 진화
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
    
    /**
     * 새 정책 생성
     */
    private EvolvedPolicy generateNewPolicy(
            PolicyEvolutionRequest request,
            AnalysisResult analysis) throws Exception {
        
        // Helper를 통한 정책 생성
        PolicyEvolutionHelper.GeneratedPolicy generated = 
            policyEvolutionHelper.generatePolicy(request.getContext(), analysis.getRequirements())
                .block();
        
        if (generated == null) {
            throw new RuntimeException("정책 생성 실패");
        }
        
        EvolvedPolicy policy = new EvolvedPolicy();
        policy.setPolicyId(generated.getId());
        policy.setContent(String.join("\n", generated.getRules()));
        policy.setConfidence(generated.getConfidence());
        policy.setVersion(1);
        policy.setEvolutionType("GENERATED");
        
        return policy;
    }
    
    /**
     * 정책 효과성 평가
     */
    private double evaluatePolicyEffectiveness(EvolvedPolicy policy, PolicyEvolutionRequest request) {
        // 간단한 효과성 평가 로직
        double baseScore = policy.getConfidence();
        
        // 컨텍스트 적합성
        double contextScore = evaluateContextFitness(policy, request);
        
        // 최종 점수
        return (baseScore + contextScore) / 2.0;
    }
    
    /**
     * 메모리에 저장
     */
    private void storeInMemory(EvolvedPolicy policy, double effectiveness) {
        // 메모리 시스템에 저장
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("policyId", policy.getPolicyId());
        metadata.put("effectiveness", effectiveness);
        metadata.put("version", policy.getVersion());
        metadata.put("type", policy.getEvolutionType());
        
        memorySystemHelper.storeInSTM(
            "policy:" + policy.getPolicyId(),
            policy,
            metadata
        ).subscribe();
        
        // 효과성이 높은 정책은 장기 메모리로
        if (effectiveness > 0.8) {
            memorySystemHelper.storeInLTM(
                "policy:" + policy.getPolicyId(),
                policy.getContent(),
                metadata
            ).subscribe();
        }
    }
    
    /**
     * 비동기 메모리 저장
     */
    private Mono<Void> storeInMemoryAsync(EvolvedPolicy policy, double effectiveness) {
        return Mono.fromRunnable(() -> storeInMemory(policy, effectiveness));
    }
    
    /**
     * 응답 생성
     */
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
    
    /**
     * 비동기 정책 검색
     */
    private Mono<List<ExistingPolicy>> searchExistingPoliciesAsync(
            PolicyEvolutionRequest request,
            AnalysisResult analysis) {
        
        return Mono.fromCallable(() -> searchExistingPolicies(request, analysis));
    }
    
    /**
     * 비동기 학습 데이터 조회
     */
    private Mono<LearningData> retrieveLearningDataAsync(PolicyEvolutionRequest request) {
        return Mono.fromCallable(() -> {
            // 학습 엔진에서 관련 데이터 조회
            LearningData data = new LearningData();
            // 실제 구현 필요
            return data;
        });
    }
    
    /**
     * 비동기 정책 진화
     */
    private Mono<EvolvedPolicy> evolveOrGeneratePolicyAsync(
            PolicyEvolutionRequest request,
            AnalysisResult analysis,
            List<ExistingPolicy> existingPolicies,
            LearningData learningData) {
        
        return Mono.fromCallable(() -> evolveOrGeneratePolicy(request, analysis, existingPolicies));
    }
    
    /**
     * 진화 프롬프트 생성
     */
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
    
    /**
     * 학습 엔진에 패턴 등록
     */
    private void registerPatternToLearningEngine(EvolvedPolicy policy) {
        // 학습 엔진에 새 패턴 등록
        // 실제 구현 필요
    }
    
    // Helper 메서드들
    
    private String analyzeThreatLevel(Map<String, Object> context) {
        // 위협 레벨 분석 로직
        return "MEDIUM";
    }
    
    private String identifyDomain(Map<String, Object> context) {
        // 도메인 식별 로직
        return "AUTHENTICATION";
    }
    
    private List<String> extractRequirements(PolicyEvolutionRequest request) {
        // 요구사항 추출 로직
        return request.getRequirements() != null ? 
            request.getRequirements() : Collections.emptyList();
    }
    
    private String generateCacheKey(PolicyEvolutionRequest request) {
        return "policy_cache_" + request.getContext().hashCode();
    }
    
    private double evaluateContextFitness(EvolvedPolicy policy, PolicyEvolutionRequest request) {
        // 컨텍스트 적합성 평가 로직
        return 0.75;
    }
    
    // ==================== 내부 클래스들 ====================
    
    /**
     * 정책 진화 요청
     */
    public static class PolicyEvolutionRequest {
        private Map<String, Object> context;
        private List<String> requirements;
        private EvolutionMode evolutionMode;
        private Map<String, Object> additionalParams;
        
        // Getters and Setters
        public Map<String, Object> getContext() { return context; }
        public void setContext(Map<String, Object> context) { this.context = context; }
        public List<String> getRequirements() { return requirements; }
        public void setRequirements(List<String> requirements) { this.requirements = requirements; }
        public EvolutionMode getEvolutionMode() { return evolutionMode; }
        public void setEvolutionMode(EvolutionMode mode) { this.evolutionMode = mode; }
        public Map<String, Object> getAdditionalParams() { return additionalParams; }
        public void setAdditionalParams(Map<String, Object> params) { this.additionalParams = params; }
    }
    
    /**
     * 정책 진화 응답
     */
    public static class PolicyEvolutionResponse {
        private String policyId;
        private String policyContent;
        private double effectiveness;
        private int version;
        private String evolutionType;
        private AnalysisResult analysis;
        private Date timestamp;
        
        // Getters and Setters
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
    
    /**
     * 진화 모드
     */
    public enum EvolutionMode {
        ADAPTIVE,    // 기존 정책 개선
        GENERATIVE,  // 새 정책 생성
        HYBRID       // 혼합 모드
    }
    
    /**
     * 분석 결과
     */
    private static class AnalysisResult {
        private String threatLevel;
        private String domain;
        private List<String> requirements;
        private String summary;
        
        // Getters and Setters
        public String getThreatLevel() { return threatLevel; }
        public void setThreatLevel(String level) { this.threatLevel = level; }
        public String getDomain() { return domain; }
        public void setDomain(String domain) { this.domain = domain; }
        public List<String> getRequirements() { return requirements; }
        public void setRequirements(List<String> requirements) { this.requirements = requirements; }
        public String getSummary() { return summary; }
        public void setSummary(String summary) { this.summary = summary; }
    }
    
    /**
     * 기존 정책
     */
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
    
    /**
     * 진화된 정책
     */
    private static class EvolvedPolicy {
        private String policyId;
        private String basePolicy;
        private String content;
        private double confidence = 0.5;
        private int version = 1;
        private String evolutionType;
        
        // Getters and Setters
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
    
    /**
     * 캐시된 정책
     */
    private static class CachedPolicy {
        private final List<ExistingPolicy> policies;
        private final long timestamp;
        private static final long CACHE_TTL = 300000; // 5분
        
        public CachedPolicy(List<ExistingPolicy> policies) {
            this.policies = policies;
            this.timestamp = System.currentTimeMillis();
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_TTL;
        }
        
        public List<ExistingPolicy> getPolicies() { return policies; }
    }
    
    /**
     * 학습 데이터
     */
    private static class LearningData {
        private List<String> patterns;
        private Map<String, Double> weights;
        
        // Getters and Setters
        public List<String> getPatterns() { return patterns; }
        public void setPatterns(List<String> patterns) { this.patterns = patterns; }
        public Map<String, Double> getWeights() { return weights; }
        public void setWeights(Map<String, Double> weights) { this.weights = weights; }
    }
}