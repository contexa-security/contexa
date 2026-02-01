package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.domain.request.IAMRequest;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexacommon.enums.DiagnosisType;
import io.contexa.contexacommon.enums.SecurityLevel;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import io.contexa.contexaiam.aiam.utils.SentenceBuffer;
import io.contexa.contexaiam.domain.dto.AiGeneratedPolicyDraftDto;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.resource.service.CompatibilityResult;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/ai/policies")
@RequiredArgsConstructor
@Slf4j
public class AiApiController {

    private final AICoreOperations<PolicyContext> aiNativeProcessor;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final ConditionCompatibilityService conditionCompatibilityService;

    @PostMapping(value = "/generate-from-text/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> generatePolicyFromTextStream(@RequestBody PolicyGenerationItem request) {

        String naturalLanguageQuery = request.naturalLanguageQuery();
        if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
            return Flux.just(ServerSentEvent.<String>builder()
                    .data("ERROR: naturalLanguageQuery is required")
                    .build());
        }

                if (request.availableItems() != null) {
                    }

        try {
            
            PolicyContext context = new PolicyContext.Builder(
                SecurityLevel.STANDARD,
                AuditRequirement.BASIC
            ).withNaturalLanguageQuery(naturalLanguageQuery).build();

            IAMRequest<PolicyContext> iamRequest =
                    (IAMRequest<PolicyContext>) new IAMRequest<>(context, "generatePolicyFromTextStream")
                        .withDiagnosisType(DiagnosisType.POLICY_GENERATION)
                        .withParameter("generationMode", "streaming")  
                        .withParameter("naturalLanguageQuery", naturalLanguageQuery)
                        .withParameter("availableItems", request.availableItems());

            SentenceBuffer sentenceBuffer = new SentenceBuffer();
            StringBuilder allData = new StringBuilder(); 
            AtomicBoolean jsonSent = new AtomicBoolean(false);
            AtomicBoolean finalResponseStarted = new AtomicBoolean(false); 
            StringBuilder markerBuffer = new StringBuilder(); 
            
            return aiNativeProcessor.processStream(iamRequest)
                    .flatMap(chunk -> {
                        String chunkStr = chunk != null ? chunk.toString() : "";

                        allData.append(chunkStr);

                        if (!finalResponseStarted.get()) {
                            markerBuffer.append(chunkStr);

                            if (markerBuffer.length() > 50) {
                                markerBuffer.delete(0, markerBuffer.length() - 50);
                            }
                            log.warn("markerBuffer: {}", markerBuffer);
                            
                            if (markerBuffer.toString().contains("###FINAL_RESPONSE###")) {
                                finalResponseStarted.set(true);
                                                            }
                        }

                        if (finalResponseStarted.get()) {
                                                        return Flux.empty(); 
                        }

                        return sentenceBuffer.processChunk(chunkStr)
                                .map(sentence -> ServerSentEvent.<String>builder()
                                        .data(sentence)
                                        .build());
                    })
                    .concatWith(
                            Mono.defer(() -> {
                                String fullData = allData.toString();

                                if (fullData.contains("###FINAL_RESPONSE###") && !jsonSent.get()) {
                                    int markerIndex = fullData.indexOf("###FINAL_RESPONSE###");
                                    String jsonPart = fullData.substring(markerIndex);

                                    jsonSent.set(true);

                                    return Mono.just(ServerSentEvent.<String>builder()
                                            .data(jsonPart)
                                            .build());
                                }

                                return Mono.empty();
                            })
                    )
                    .concatWith(
                            sentenceBuffer.flush()
                                    .map(remaining -> ServerSentEvent.<String>builder()
                                            .data(remaining)
                                            .build())
                    )
                    .concatWith(
                            Mono.just(ServerSentEvent.<String>builder()
                                    .data("[DONE]")
                                    .build())
                    )
                    .onErrorResume(error -> {
                        log.error("스트리밍 처리 중 오류", error);
                        String errorMessage = error instanceof Throwable ? 
                            ((Throwable) error).getMessage() : error.toString();
                        return Flux.just(ServerSentEvent.<String>builder()
                                .data("ERROR: " + errorMessage)
                                .build());
                    });
        } catch (Exception e) {
            log.error("AI 스트리밍 정책 생성 실패", e);
            return Flux.just(ServerSentEvent.<String>builder()
                    .data("ERROR: " + e.getMessage())
                    .build());
        }
    }

    @PostMapping("/generate-from-text")
    public Mono<ResponseEntity<AiGeneratedPolicyDraftDto>> generatePolicyFromText(@RequestBody PolicyGenerationItem request) {

        String naturalLanguageQuery = request.naturalLanguageQuery();
        if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
            return Mono.just(ResponseEntity.badRequest().build());
        }

                if (request.availableItems() != null) {
                    }

        return Mono.fromCallable(() -> {
            
            PolicyContext context = new PolicyContext.Builder(
                SecurityLevel.STANDARD,
                AuditRequirement.BASIC
            ).withNaturalLanguageQuery(naturalLanguageQuery).build();

            return (AIRequest<PolicyContext>) new AIRequest<>(context, "generatePolicyFromText", context.getOrganizationId())
                    .withDiagnosisType(DiagnosisType.POLICY_GENERATION)
                    .withParameter("generationMode", "standard")
                    .withParameter("naturalLanguageQuery", naturalLanguageQuery)
                    .withParameter("availableItems", request.availableItems());
        })
        .flatMap(aiRequest -> {
            
            return aiNativeProcessor.process(aiRequest, AIResponse.class);
        })
        .map(response -> {
            if (response instanceof PolicyResponse policyResponse) {

                BusinessPolicyDto policyData = policyResponse.getPolicyData();
                Map<String, String> roleMap = policyResponse.getRoleIdToNameMap();
                Map<String, String> permissionMap = policyResponse.getPermissionIdToNameMap();
                Map<String, String> conditionMap = policyResponse.getConditionIdToNameMap();

                if (policyData == null) {
                    log.error("PolicyResponse 에서 policyData가 null 입니다");
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
                }
                
                roleMap = roleMap != null ? roleMap : new HashMap<>();
                permissionMap = permissionMap != null ? permissionMap : new HashMap<>();
                conditionMap = conditionMap != null ? conditionMap : new HashMap<>();

                AiGeneratedPolicyDraftDto result =
                    new AiGeneratedPolicyDraftDto(
                        policyData, roleMap, permissionMap, conditionMap
                    );

                                return ResponseEntity.ok(result);
            }

            log.error("예상하지 못한 응답 타입: {} (예상: PolicyResponse)", response.getClass().getSimpleName());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        });
    }

    @PostMapping("/recommend-conditions")
    public Mono<ResponseEntity<Map<String, Object>>> recommendConditions(@RequestBody RecommendConditionsRequest request) {
        
        return Mono.fromCallable(() -> {
            
            ManagedResource resource = managedResourceRepository.findByResourceIdentifier(request.resourceIdentifier())
                    .orElseThrow(() -> new IllegalArgumentException("Resource not found: " + request.resourceIdentifier()));

            List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();

            Map<Long, CompatibilityResult> compatibilityResults =
                conditionCompatibilityService.checkBatchCompatibility(allConditions, resource);

            Map<ConditionTemplate.ConditionClassification, List<RecommendedCondition>> recommendedByClass =
                new EnumMap<>(ConditionTemplate.ConditionClassification.class);

            for (ConditionTemplate condition : allConditions) {
                CompatibilityResult result = compatibilityResults.get(condition.getId());
                if (result != null && result.isCompatible()) {
                    
                    double matchingScore = calculateRecommendationScore(condition, request.context());

                    RecommendedCondition recommendedCondition = new RecommendedCondition(
                        condition.getId(),
                        condition.getName(),
                        condition.getDescription(),
                        condition.getSpelTemplate(),
                        condition.getClassification(),
                        condition.getRiskLevel(),
                        condition.getComplexityScore(),
                        result.getReason(),
                        matchingScore
                    );

                    recommendedByClass.computeIfAbsent(condition.getClassification(),
                        k -> new ArrayList<>()).add(recommendedCondition);
                }
            }

            recommendedByClass.values().forEach(list ->
                list.sort((a, b) -> Double.compare(b.recommendationScore(), a.recommendationScore())));

            Map<String, Object> response = new HashMap<>();
            response.put("resourceIdentifier", request.resourceIdentifier());
            response.put("resourceFriendlyName", resource.getFriendlyName());
            response.put("recommendedConditions", recommendedByClass);
            response.put("totalRecommended", recommendedByClass.values().stream()
                .mapToInt(List::size).sum());
            response.put("statistics", calculateRecommendationStatistics(recommendedByClass));

            return ResponseEntity.ok(response);
        })
        .onErrorResume(error -> {
            log.error("조건 비동기 추천 중 오류 발생", error);
            return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "조건 추천 중 오류가 발생했습니다: " + error.getMessage())));
        });
    }

    private double calculateRecommendationScore(ConditionTemplate condition, String context) {
        double score = 0.0;

        switch (condition.getClassification()) {
            case UNIVERSAL -> score += 1.0;           
            case CONTEXT_DEPENDENT -> score += 0.7;   
            case CUSTOM_COMPLEX -> score += 0.4;      
        }

        if (condition.getRiskLevel() != null) {
            switch (condition.getRiskLevel()) {
                case LOW -> score += 0.3;
                case MEDIUM -> score += 0.1;
                case HIGH -> score -= 0.2;
            }
        }

        if (condition.getComplexityScore() != null) {
            score += (10 - condition.getComplexityScore()) * 0.05;
        }

        if (context != null && !context.trim().isEmpty()) {
            String lowerContext = context.toLowerCase();
            String lowerName = condition.getName().toLowerCase();
            String lowerDesc = condition.getDescription() != null ? condition.getDescription().toLowerCase() : "";

            if (lowerName.contains("시간") && lowerContext.contains("time")) score += 0.5;
            if (lowerName.contains("ip") && lowerContext.contains("ip")) score += 0.5;
            if (lowerName.contains("본인") && lowerContext.contains("owner")) score += 0.5;
            if (lowerDesc.contains(lowerContext) || lowerName.contains(lowerContext)) score += 0.3;
        }

        return Math.max(0.0, Math.min(2.0, score)); 
    }

    @PostMapping("/smart-match-conditions")
    public Mono<ResponseEntity<Map<String, Object>>> smartMatchConditions(@RequestBody SmartMatchRequest request) {
        
        return Mono.fromCallable(() -> {
            
            ManagedResource resource = managedResourceRepository.findByResourceIdentifier(request.resourceIdentifier())
                    .orElseThrow(() -> new IllegalArgumentException("Resource not found: " + request.resourceIdentifier()));

            List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();

            Map<Long, CompatibilityResult> compatibilityResults =
                conditionCompatibilityService.checkBatchCompatibility(allConditions, resource);

            List<SmartMatchedCondition> smartMatched = new ArrayList<>();

            for (ConditionTemplate condition : allConditions) {
                CompatibilityResult result = compatibilityResults.get(condition.getId());
                if (result != null && result.isCompatible()) {
                    double smartScore = calculateSmartMatchingScore(condition, request.permissionName(), request.context());

                    SmartMatchedCondition matchedCondition = new SmartMatchedCondition(
                        condition.getId(),
                        condition.getName(),
                        condition.getDescription(),
                        condition.getSpelTemplate(),
                        condition.getClassification(),
                        condition.getRiskLevel(),
                        condition.getComplexityScore(),
                        result.getReason(),
                        smartScore,
                        calculateMatchingReason(condition, request.permissionName())
                    );

                    smartMatched.add(matchedCondition);
                }
            }

            smartMatched.sort((a, b) -> Double.compare(b.smartMatchingScore(), a.smartMatchingScore()));

            Map<String, Object> response = new HashMap<>();
            response.put("permissionName", request.permissionName());
            response.put("resourceIdentifier", request.resourceIdentifier());
            response.put("resourceFriendlyName", resource.getFriendlyName());
            response.put("smartMatchedConditions", smartMatched);
            response.put("totalMatched", smartMatched.size());
            response.put("highScoreConditions", smartMatched.stream()
                .filter(c -> c.smartMatchingScore() >= 3.0)
                .collect(Collectors.toList()));

            return ResponseEntity.ok(response);
        })
        .onErrorResume(error -> {
            log.error("스마트 비동기 매칭 중 오류 발생", error);
            return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "스마트 매칭 중 오류가 발생했습니다: " + error.getMessage())));
        });
    }

    private double calculateSmartMatchingScore(ConditionTemplate condition, String permissionName, String context) {
        double score = calculateRecommendationScore(condition, context);

        if (permissionName == null || condition.getName() == null) {
            return score;
        }

        String lowerPermission = permissionName.toLowerCase();
        String lowerCondition = condition.getName().toLowerCase();

        String cleanPermission = lowerPermission.replaceAll("[^가-힣a-z0-9]", "");
        String cleanCondition = lowerCondition.replaceAll("[^가-힣a-z0-9]", "");

        if (cleanCondition.contains(cleanPermission) || cleanPermission.contains(cleanCondition)) {
            score += 3.0; 
        }

        String[] permissionWords = lowerPermission.split("\\s+");
        String[] conditionWords = lowerCondition.split("\\s+");

        int matchedWords = 0;
        for (String pWord : permissionWords) {
            if (pWord.length() > 1) { 
                for (String cWord : conditionWords) {
                    if (cWord.contains(pWord) || pWord.contains(cWord)) {
                        matchedWords++;
                        break;
                    }
                }
            }
        }

        if (matchedWords > 0) {
            score += (double) matchedWords / permissionWords.length * 2.0;
        }

        if (containsEntity(lowerPermission, "사용자") && containsEntity(lowerCondition, "사용자")) score += 1.0;
        if (containsEntity(lowerPermission, "문서") && containsEntity(lowerCondition, "문서")) score += 1.0;
        if (containsEntity(lowerPermission, "그룹") && containsEntity(lowerCondition, "그룹")) score += 1.0;
        if (containsEntity(lowerPermission, "권한") && containsEntity(lowerCondition, "권한")) score += 1.0;
        if (containsEntity(lowerPermission, "역할") && containsEntity(lowerCondition, "역할")) score += 1.0;
        if (containsEntity(lowerPermission, "정책") && containsEntity(lowerCondition, "정책")) score += 1.0;

        if (containsAction(lowerPermission, "수정") && containsAction(lowerCondition, "수정")) score += 1.5;
        if (containsAction(lowerPermission, "삭제") && containsAction(lowerCondition, "삭제")) score += 1.5;
        if (containsAction(lowerPermission, "조회") && containsAction(lowerCondition, "조회")) score += 1.5;
        if (containsAction(lowerPermission, "생성") && containsAction(lowerCondition, "생성")) score += 1.5;
        if (containsAction(lowerPermission, "관리") && containsAction(lowerCondition, "관리")) score += 1.5;

        if (lowerPermission.contains("본인") && lowerCondition.contains("본인")) score += 2.0;
        if (lowerPermission.contains("소유자") && lowerCondition.contains("소유자")) score += 2.0;
        if (lowerPermission.contains("관리자") && lowerCondition.contains("관리자")) score += 1.5;

        return Math.max(0.0, Math.min(5.0, score)); 
    }

    private String calculateMatchingReason(ConditionTemplate condition, String permissionName) {
        if (permissionName == null || condition.getName() == null) {
            return "기본 추천";
        }

        List<String> reasons = new ArrayList<>();
        String lowerPermission = permissionName.toLowerCase();
        String lowerCondition = condition.getName().toLowerCase();

        if (containsEntity(lowerPermission, "사용자") && containsEntity(lowerCondition, "사용자")) {
            reasons.add("사용자 엔티티 매칭");
        }
        if (containsEntity(lowerPermission, "문서") && containsEntity(lowerCondition, "문서")) {
            reasons.add("문서 엔티티 매칭");
        }

        if (containsAction(lowerPermission, "수정") && containsAction(lowerCondition, "수정")) {
            reasons.add("수정 액션 매칭");
        }
        if (containsAction(lowerPermission, "삭제") && containsAction(lowerCondition, "삭제")) {
            reasons.add("삭제 액션 매칭");
        }
        if (containsAction(lowerPermission, "조회") && containsAction(lowerCondition, "조회")) {
            reasons.add("조회 액션 매칭");
        }

        if (lowerPermission.contains("본인") && lowerCondition.contains("본인")) {
            reasons.add("본인 확인 패턴");
        }

        return reasons.isEmpty() ? "일반 호환성" : String.join(", ", reasons);
    }

    private static final Map<String, String[]> ENTITY_MAPPING;

    static {
        ENTITY_MAPPING = new HashMap<>();
        ENTITY_MAPPING.put("사용자", new String[]{"user", "회원"});
        ENTITY_MAPPING.put("문서", new String[]{"document", "파일", "file"});
        ENTITY_MAPPING.put("그룹", new String[]{"group", "팀"});
        ENTITY_MAPPING.put("파일", new String[]{"file", "document", "문서"});
        ENTITY_MAPPING.put("게시물", new String[]{"post", "board", "게시판"});
        ENTITY_MAPPING.put("데이터", new String[]{"data", "정보", "info"});
    }

    private boolean containsEntity(String text, String entity) {
        
        if (text.contains(entity)) {
            return true;
        }

        String[] synonyms = ENTITY_MAPPING.get(entity);
        if (synonyms != null) {
            for (String synonym : synonyms) {
                if (text.contains(synonym)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    private boolean containsAction(String text, String action) {
        switch (action) {
            case "수정":
                return text.contains("수정") || text.contains("edit") || text.contains("update") || text.contains("modify");
            case "삭제":
                return text.contains("삭제") || text.contains("delete") || text.contains("remove");
            case "조회":
                return text.contains("조회") || text.contains("read") || text.contains("view") || text.contains("get") || text.contains("find");
            case "생성":
                return text.contains("생성") || text.contains("create") || text.contains("add") || text.contains("insert");
            default:
                return text.contains(action);
        }
    }

    private Map<String, Object> calculateRecommendationStatistics(
            Map<ConditionTemplate.ConditionClassification, List<RecommendedCondition>> recommendedByClass) {

        Map<String, Object> stats = new HashMap<>();

        int totalCount = recommendedByClass.values().stream().mapToInt(List::size).sum();
        stats.put("totalRecommended", totalCount);

        Map<String, Integer> countByClass = new HashMap<>();
        for (Map.Entry<ConditionTemplate.ConditionClassification, List<RecommendedCondition>> entry : recommendedByClass.entrySet()) {
            countByClass.put(entry.getKey().name(), entry.getValue().size());
        }
        stats.put("countByClassification", countByClass);

        double avgScore = recommendedByClass.values().stream()
            .flatMap(List::stream)
            .mapToDouble(RecommendedCondition::recommendationScore)
            .average()
            .orElse(0.0);
        stats.put("averageRecommendationScore", Math.round(avgScore * 100.0) / 100.0);

        return stats;
    }

    public record RecommendConditionsRequest(
        String resourceIdentifier,
        String context  
    ) {}

    public record RecommendedCondition(
        Long id,
        String name,
        String description,
        String spelTemplate,
        ConditionTemplate.ConditionClassification classification,
        ConditionTemplate.RiskLevel riskLevel,
        Integer complexityScore,
        String compatibilityReason,
        double recommendationScore
    ) {}

    public record SmartMatchRequest(
        String permissionName,
        String resourceIdentifier,
        String context
    ) {}

    public record SmartMatchedCondition(
        Long id,
        String name,
        String description,
        String spelTemplate,
        ConditionTemplate.ConditionClassification classification,
        ConditionTemplate.RiskLevel riskLevel,
        Integer complexityScore,
        String compatibilityReason,
        double smartMatchingScore,
        String matchingReason
    ) {}

    private Flux<ServerSentEvent<String>> createStreamingFromText(String text) {
        if (text == null || text.isEmpty()) {
            return Flux.just(ServerSentEvent.<String>builder()
                    .data("ERROR: Empty response")
                    .build());
        }

        String[] words = text.split("\\s+");
        int chunkSize = Math.max(1, words.length / 20); 

        return Flux.range(0, (words.length + chunkSize - 1) / chunkSize)
                .delayElements(java.time.Duration.ofMillis(100)) 
                .map(i -> {
                    int start = i * chunkSize;
                    int end = Math.min(start + chunkSize, words.length);
                    StringBuilder chunk = new StringBuilder();
                    for (int j = start; j < end; j++) {
                        chunk.append(words[j]).append(" ");
                    }
                    return ServerSentEvent.<String>builder()
                            .data(chunk.toString().trim())
                            .build();
                })
                .concatWith(
                    Mono.just(ServerSentEvent.<String>builder()
                            .data("[DONE]")
                            .build())
                );
    }

    private Flux<ServerSentEvent<String>> createFallbackStreamingFromRequest(String naturalLanguageQuery, PolicyGenerationItem.AvailableItems availableItems) {
        log.warn("Fallback 스트리밍 생성: {}", naturalLanguageQuery);

        return Flux.create(sink -> {
            try {
                
                sink.next(ServerSentEvent.<String>builder()
                        .data("AI가 요청을 분석하고 있습니다...")
                        .build());

                Mono.delay(java.time.Duration.ofMillis(500))
                        .doOnNext(tick -> {
                            sink.next(ServerSentEvent.<String>builder()
                                    .data("사용 가능한 역할과 권한을 검토하고 있습니다...")
                                    .build());
                        })
                        .then(Mono.delay(java.time.Duration.ofMillis(500)))
                        .doOnNext(tick -> {
                            sink.next(ServerSentEvent.<String>builder()
                                    .data("정책 구조를 생성하고 있습니다...")
                                    .build());
                        })
                        .then(Mono.delay(java.time.Duration.ofMillis(500)))
                        .doOnNext(tick -> {
                            
                            String basicJson = """
                                ===JSON시작===
                                {
                                  "policyName": "AI 생성 정책 (Fallback)",
                                  "description": "AI가 분석한 요구사항: """ + naturalLanguageQuery + """
                                ",
                                  "roleIds": [],
                                  "permissionIds": [],
                                  "conditions": {},
                                  "effect": "ALLOW"
                                }
                                ===JSON끝===
                                """;

                            sink.next(ServerSentEvent.<String>builder()
                                    .data(basicJson)
                                    .build());
                        })
                        .then(Mono.delay(java.time.Duration.ofMillis(200)))
                        .doOnNext(tick -> {
                            sink.next(ServerSentEvent.<String>builder()
                                    .data("[DONE]")
                                    .build());
                            sink.complete();
                        })
                        .subscribe();

            } catch (Exception e) {
                log.error("Fallback 스트리밍 생성 실패", e);
                sink.next(ServerSentEvent.<String>builder()
                        .data("ERROR: " + e.getMessage())
                        .build());
                sink.complete();
            }
        });
    }
}