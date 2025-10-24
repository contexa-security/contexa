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

/**
 * AI 정책 생성 API 컨트롤러 - 완전 통합 아키텍처
 *
 * 모든 AI 진입점은 오직 aiNativeIAMOperations.execute 사용
 * 스트리밍/동기 모두 동일한 Master Brain 경로
 */
@RestController
@RequestMapping("/api/ai/policies")
@RequiredArgsConstructor
@Slf4j
public class AiApiController {

    private final AICoreOperations<PolicyContext> aiNativeProcessor;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final ConditionCompatibilityService conditionCompatibilityService;

    /**
     * AI로 정책 초안을 스트리밍 방식으로 생성합니다 - 완전 통합 아키텍처
     *
     * aiNativeIAMOperations.execute 유일한 진입점 사용 (스트리밍 모드)
     */
    @PostMapping(value = "/generate-from-text/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> generatePolicyFromTextStream(@RequestBody PolicyGenerationItem request) {

        String naturalLanguageQuery = request.naturalLanguageQuery();
        if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
            return Flux.just(ServerSentEvent.<String>builder()
                    .data("ERROR: naturalLanguageQuery is required")
                    .build());
        }

        log.info("AI 스트리밍 정책 생성 요청 - Master Brain 단일 진입점 사용: {}", naturalLanguageQuery);
        if (request.availableItems() != null) {
            log.info("사용 가능한 항목들: 역할 {}개, 권한 {}개, 조건 {}개",
                request.availableItems().roles() != null ? request.availableItems().roles().size() : 0,
                request.availableItems().permissions() != null ? request.availableItems().permissions().size() : 0,
                request.availableItems().conditions() != null ? request.availableItems().conditions().size() : 0);
        }

        try {
            // IAMRequest 생성 - 스트리밍 모드로 설정
            PolicyContext context = new PolicyContext.Builder(
                SecurityLevel.STANDARD,
                AuditRequirement.BASIC
            ).withNaturalLanguageQuery(naturalLanguageQuery).build();

            IAMRequest<PolicyContext> iamRequest =
                    (IAMRequest<PolicyContext>) new IAMRequest<>(context, "generatePolicyFromTextStream")
                        .withDiagnosisType(DiagnosisType.POLICY_GENERATION)
                        .withParameter("generationMode", "streaming")  // 스트리밍 모드 지정
                        .withParameter("naturalLanguageQuery", naturalLanguageQuery)
                        .withParameter("availableItems", request.availableItems());

            // 올바른 흐름: executeStream 사용 + 문장 단위 버퍼링 (SecurityCopilot 발전된 방식)
            SentenceBuffer sentenceBuffer = new SentenceBuffer();
            StringBuilder allData = new StringBuilder(); // 모든 데이터 누적
            AtomicBoolean jsonSent = new AtomicBoolean(false);
            AtomicBoolean finalResponseStarted = new AtomicBoolean(false); // FINAL_RESPONSE 모드 추적
            StringBuilder markerBuffer = new StringBuilder(); // 마커 감지용 버퍼
            
            return aiNativeProcessor.processStream(iamRequest)
                    .flatMap(chunk -> {
                        String chunkStr = chunk != null ? chunk.toString() : "";

                        log.debug("[RECEIVED] 청크 길이: {}, 내용: {}",
                                chunkStr.length(),
                                chunkStr.length() > 50 ? chunkStr.substring(0, 50) + "..." : chunkStr);

                        // 모든 데이터를 누적
                        allData.append(chunkStr);

                        // 효율적인 마커 감지 (성능 최적화)
                        if (!finalResponseStarted.get()) {
                            markerBuffer.append(chunkStr);

                            // 마커 버퍼가 너무 크면 앞부분 제거 (최근 50자만 유지)
                            if (markerBuffer.length() > 50) {
                                markerBuffer.delete(0, markerBuffer.length() - 50);
                            }
                            log.warn("markerBuffer: {}", markerBuffer);
                            // 마커 감지
                            if (markerBuffer.toString().contains("###FINAL_RESPONSE###")) {
                                finalResponseStarted.set(true);
                                log.info("[FINAL-MODE] FINAL_RESPONSE 모드 시작 - 이후 청크들은 sentenceBuffer 처리 제외");
                            }
                        }

                        // FINAL_RESPONSE 모드에서는 sentenceBuffer 처리 제외 (중복 방지)
                        if (finalResponseStarted.get()) {
                            log.debug("[SKIP-SENTENCE] FINAL_RESPONSE 모드 - sentenceBuffer 처리 스킵");
                            return Flux.empty(); // 빈 스트림 반환하여 이 청크는 sentenceBuffer로 처리하지 않음
                        }

                        // 일반 텍스트만 sentenceBuffer로 처리하여 스트리밍
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

    /**
     * AI로 정책 초안을 비동기 방식으로 생성합니다 - 단일 AI 진단
     */
    @PostMapping("/generate-from-text")
    public Mono<ResponseEntity<AiGeneratedPolicyDraftDto>> generatePolicyFromText(@RequestBody PolicyGenerationItem request) {

        String naturalLanguageQuery = request.naturalLanguageQuery();
        if (naturalLanguageQuery == null || naturalLanguageQuery.trim().isEmpty()) {
            return Mono.just(ResponseEntity.badRequest().build());
        }

        log.info("Controller: AI 정책 비동기 생성 요청을 Master Brain 단일 진입점에 위임 - {}", naturalLanguageQuery);
        if (request.availableItems() != null) {
            log.info("사용 가능한 항목들: 역할 {}개, 권한 {}개, 조건 {}개",
                request.availableItems().roles() != null ? request.availableItems().roles().size() : 0,
                request.availableItems().permissions() != null ? request.availableItems().permissions().size() : 0,
                request.availableItems().conditions() != null ? request.availableItems().conditions().size() : 0);
        }

        return Mono.fromCallable(() -> {
            // 범용 AIRequest 생성 - aicore 범용성 유지
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
            // 범용 AI 처리 - 도메인 무관
            return aiNativeProcessor.process(aiRequest, AIResponse.class);
        })
        .map(response -> {
            if (response instanceof PolicyResponse policyResponse) {

                BusinessPolicyDto policyData = policyResponse.getPolicyData();
                Map<String, String> roleMap = policyResponse.getRoleIdToNameMap();
                Map<String, String> permissionMap = policyResponse.getPermissionIdToNameMap();
                Map<String, String> conditionMap = policyResponse.getConditionIdToNameMap();

                // null 체크 및 기본값 설정
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

                log.info("비동기 정책 생성 성공: {}", policyData.getPolicyName());
                return ResponseEntity.ok(result);
            }

            // 응답 타입이 예상과 다른 경우 오류 처리
            log.error("예상하지 못한 응답 타입: {} (예상: PolicyResponse)", response.getClass().getSimpleName());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        });
    }



    /**
     * 특정 리소스에 대한 실시간 조건 추천 API - 완전 비동기 처리
     */
    @PostMapping("/recommend-conditions")
    public Mono<ResponseEntity<Map<String, Object>>> recommendConditions(@RequestBody RecommendConditionsRequest request) {
        log.info("조건 비동기 추천 요청: 리소스={}, 컨텍스트={}", request.resourceIdentifier(), request.context());

        return Mono.fromCallable(() -> {
            // 리소스 정보 조회
            ManagedResource resource = managedResourceRepository.findByResourceIdentifier(request.resourceIdentifier())
                    .orElseThrow(() -> new IllegalArgumentException("Resource not found: " + request.resourceIdentifier()));

            // 모든 조건 템플릿 조회
            List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();

            // 호환성 검사 수행
            Map<Long, CompatibilityResult> compatibilityResults =
                conditionCompatibilityService.checkBatchCompatibility(allConditions, resource);

            // 호환 가능한 조건들을 분류별로 그룹화
            Map<ConditionTemplate.ConditionClassification, List<RecommendedCondition>> recommendedByClass =
                new EnumMap<>(ConditionTemplate.ConditionClassification.class);

            for (ConditionTemplate condition : allConditions) {
                CompatibilityResult result = compatibilityResults.get(condition.getId());
                if (result != null && result.isCompatible()) {
                    // 개선: 스마트 매칭 점수 계산 (권한명 정보 없을 시 기본 추천 점수 사용)
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

            // 각 분류별로 추천 점수순 정렬
            recommendedByClass.values().forEach(list ->
                list.sort((a, b) -> Double.compare(b.recommendationScore(), a.recommendationScore())));

            Map<String, Object> response = new HashMap<>();
            response.put("resourceIdentifier", request.resourceIdentifier());
            response.put("resourceFriendlyName", resource.getFriendlyName());
            response.put("recommendedConditions", recommendedByClass);
            response.put("totalRecommended", recommendedByClass.values().stream()
                .mapToInt(List::size).sum());
            response.put("statistics", calculateRecommendationStatistics(recommendedByClass));

            log.info("조건 비동기 추천 완료: {} 개 조건 추천",
                recommendedByClass.values().stream().mapToInt(List::size).sum());

            return ResponseEntity.ok(response);
        })
        .onErrorResume(error -> {
            log.error("조건 비동기 추천 중 오류 발생", error);
            return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "조건 추천 중 오류가 발생했습니다: " + error.getMessage())));
        });
    }

    /**
     * 조건의 추천 점수를 계산합니다.
     */
    private double calculateRecommendationScore(ConditionTemplate condition, String context) {
        double score = 0.0;

        // 기본 점수 (분류별)
        switch (condition.getClassification()) {
            case UNIVERSAL -> score += 1.0;           // 범용 조건은 높은 점수
            case CONTEXT_DEPENDENT -> score += 0.7;   // 컨텍스트 의존은 중간 점수
            case CUSTOM_COMPLEX -> score += 0.4;      // 복잡한 조건은 낮은 점수
        }

        // 위험도에 따른 점수 조정
        if (condition.getRiskLevel() != null) {
            switch (condition.getRiskLevel()) {
                case LOW -> score += 0.3;
                case MEDIUM -> score += 0.1;
                case HIGH -> score -= 0.2;
            }
        }

        // 복잡도에 따른 점수 조정 (낮을수록 좋음)
        if (condition.getComplexityScore() != null) {
            score += (10 - condition.getComplexityScore()) * 0.05;
        }

        // 컨텍스트 기반 점수 조정
        if (context != null && !context.trim().isEmpty()) {
            String lowerContext = context.toLowerCase();
            String lowerName = condition.getName().toLowerCase();
            String lowerDesc = condition.getDescription() != null ? condition.getDescription().toLowerCase() : "";

            // 키워드 매칭
            if (lowerName.contains("시간") && lowerContext.contains("time")) score += 0.5;
            if (lowerName.contains("ip") && lowerContext.contains("ip")) score += 0.5;
            if (lowerName.contains("본인") && lowerContext.contains("owner")) score += 0.5;
            if (lowerDesc.contains(lowerContext) || lowerName.contains(lowerContext)) score += 0.3;
        }

        return Math.max(0.0, Math.min(2.0, score)); // 0.0 ~ 2.0 범위로 제한
    }

    /**
     * 개선: 권한명과 조건명 스마트 매칭 API
     */
    @PostMapping("/smart-match-conditions")
    public Mono<ResponseEntity<Map<String, Object>>> smartMatchConditions(@RequestBody SmartMatchRequest request) {
        log.info("스마트 조건 비동기 매칭 요청: 권한={}, 리소스={}", request.permissionName(), request.resourceIdentifier());

        return Mono.fromCallable(() -> {
            // 리소스 정보 조회
            ManagedResource resource = managedResourceRepository.findByResourceIdentifier(request.resourceIdentifier())
                    .orElseThrow(() -> new IllegalArgumentException("Resource not found: " + request.resourceIdentifier()));

            // 모든 조건 템플릿 조회
            List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();

            // 호환성 검사 수행
            Map<Long, CompatibilityResult> compatibilityResults =
                conditionCompatibilityService.checkBatchCompatibility(allConditions, resource);

            // 호환 가능한 조건들에 대해 스마트 매칭 점수 계산
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

            // 스마트 매칭 점수순으로 정렬
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

            log.info("스마트 비동기 매칭 완료: {} 개 조건, 고점수: {} 개",
                smartMatched.size(),
                smartMatched.stream().mapToLong(c -> c.smartMatchingScore() >= 3.0 ? 1 : 0).sum());

            return ResponseEntity.ok(response);
        })
        .onErrorResume(error -> {
            log.error("스마트 비동기 매칭 중 오류 발생", error);
            return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "스마트 매칭 중 오류가 발생했습니다: " + error.getMessage())));
        });
    }

    /**
     * 개선: 권한명과 조건명 스마트 매칭 점수 계산
     */
    private double calculateSmartMatchingScore(ConditionTemplate condition, String permissionName, String context) {
        double score = calculateRecommendationScore(condition, context);

        if (permissionName == null || condition.getName() == null) {
            return score;
        }

        String lowerPermission = permissionName.toLowerCase();
        String lowerCondition = condition.getName().toLowerCase();

        // 핵심 개선: 권한명-조건명 의미적 매칭

        // 1. 완전 일치 (권한명이 조건명에 포함되거나 그 반대)
        String cleanPermission = lowerPermission.replaceAll("[^가-힣a-z0-9]", "");
        String cleanCondition = lowerCondition.replaceAll("[^가-힣a-z0-9]", "");

        if (cleanCondition.contains(cleanPermission) || cleanPermission.contains(cleanCondition)) {
            score += 3.0; // 높은 점수
        }

        // 2. 핵심 키워드 매칭
        String[] permissionWords = lowerPermission.split("\\s+");
        String[] conditionWords = lowerCondition.split("\\s+");

        int matchedWords = 0;
        for (String pWord : permissionWords) {
            if (pWord.length() > 1) { // 한 글자 단어는 제외
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

        // 3. 엔티티 타입 매칭 (사용자 ↔ User)
        if (containsEntity(lowerPermission, "사용자") && containsEntity(lowerCondition, "사용자")) score += 1.0;
        if (containsEntity(lowerPermission, "문서") && containsEntity(lowerCondition, "문서")) score += 1.0;
        if (containsEntity(lowerPermission, "그룹") && containsEntity(lowerCondition, "그룹")) score += 1.0;
        if (containsEntity(lowerPermission, "권한") && containsEntity(lowerCondition, "권한")) score += 1.0;
        if (containsEntity(lowerPermission, "역할") && containsEntity(lowerCondition, "역할")) score += 1.0;
        if (containsEntity(lowerPermission, "정책") && containsEntity(lowerCondition, "정책")) score += 1.0;

        // 4. 액션 타입 매칭 (수정 ↔ 수정, 삭제 ↔ 삭제)
        if (containsAction(lowerPermission, "수정") && containsAction(lowerCondition, "수정")) score += 1.5;
        if (containsAction(lowerPermission, "삭제") && containsAction(lowerCondition, "삭제")) score += 1.5;
        if (containsAction(lowerPermission, "조회") && containsAction(lowerCondition, "조회")) score += 1.5;
        if (containsAction(lowerPermission, "생성") && containsAction(lowerCondition, "생성")) score += 1.5;
        if (containsAction(lowerPermission, "관리") && containsAction(lowerCondition, "관리")) score += 1.5;

        // 5. 특수 패턴 매칭
        if (lowerPermission.contains("본인") && lowerCondition.contains("본인")) score += 2.0;
        if (lowerPermission.contains("소유자") && lowerCondition.contains("소유자")) score += 2.0;
        if (lowerPermission.contains("관리자") && lowerCondition.contains("관리자")) score += 1.5;

        return Math.max(0.0, Math.min(5.0, score)); // 확장된 범위로 제한
    }

    /**
     * 매칭 이유 계산
     */
    private String calculateMatchingReason(ConditionTemplate condition, String permissionName) {
        if (permissionName == null || condition.getName() == null) {
            return "기본 추천";
        }

        List<String> reasons = new ArrayList<>();
        String lowerPermission = permissionName.toLowerCase();
        String lowerCondition = condition.getName().toLowerCase();

        // 엔티티 매칭
        if (containsEntity(lowerPermission, "사용자") && containsEntity(lowerCondition, "사용자")) {
            reasons.add("사용자 엔티티 매칭");
        }
        if (containsEntity(lowerPermission, "문서") && containsEntity(lowerCondition, "문서")) {
            reasons.add("문서 엔티티 매칭");
        }

        // 액션 매칭
        if (containsAction(lowerPermission, "수정") && containsAction(lowerCondition, "수정")) {
            reasons.add("수정 액션 매칭");
        }
        if (containsAction(lowerPermission, "삭제") && containsAction(lowerCondition, "삭제")) {
            reasons.add("삭제 액션 매칭");
        }
        if (containsAction(lowerPermission, "조회") && containsAction(lowerCondition, "조회")) {
            reasons.add("조회 액션 매칭");
        }

        // 특수 패턴
        if (lowerPermission.contains("본인") && lowerCondition.contains("본인")) {
            reasons.add("본인 확인 패턴");
        }

        return reasons.isEmpty() ? "일반 호환성" : String.join(", ", reasons);
    }

    // 동적 엔티티 매핑 (하드코딩 완전 제거)
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
    
    /**
     * 엔티티 타입 포함 여부 확인 (동적 매핑 사용)
     */
    private boolean containsEntity(String text, String entity) {
        // 기본 매칭
        if (text.contains(entity)) {
            return true;
        }
        
        // 동적 매핑 사용
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

    /**
     * 액션 타입 포함 여부 확인
     */
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

    /**
     * 추천 통계를 계산합니다.
     */
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

        // 평균 추천 점수
        double avgScore = recommendedByClass.values().stream()
            .flatMap(List::stream)
            .mapToDouble(RecommendedCondition::recommendationScore)
            .average()
            .orElse(0.0);
        stats.put("averageRecommendationScore", Math.round(avgScore * 100.0) / 100.0);

        return stats;
    }

    /**
     * 조건 추천 요청 DTO
     */
    public record RecommendConditionsRequest(
        String resourceIdentifier,
        String context  // 추가 컨텍스트 (예: "time-based", "ip-restriction" 등)
    ) {}

    /**
     * 추천된 조건 정보 DTO
     */
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

    /**
     * 스마트 매칭 요청 DTO
     */
    public record SmartMatchRequest(
        String permissionName,
        String resourceIdentifier,
        String context
    ) {}

    /**
     * 스마트 매칭된 조건 정보 DTO
     */
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

    /**
     * 문자열을 스트리밍 형태로 변환하는 헬퍼 메서드
     */
    private Flux<ServerSentEvent<String>> createStreamingFromText(String text) {
        if (text == null || text.isEmpty()) {
            return Flux.just(ServerSentEvent.<String>builder()
                    .data("ERROR: Empty response")
                    .build());
        }

        // 텍스트를 청크 단위로 분할하여 스트리밍 효과 연출
        String[] words = text.split("\\s+");
        int chunkSize = Math.max(1, words.length / 20); // 20개 정도의 청크로 분할

        return Flux.range(0, (words.length + chunkSize - 1) / chunkSize)
                .delayElements(java.time.Duration.ofMillis(100)) // 100ms 간격
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

    /**
     * Fallback 스트리밍 생성 (직접 요청 처리)
     */
    private Flux<ServerSentEvent<String>> createFallbackStreamingFromRequest(String naturalLanguageQuery, PolicyGenerationItem.AvailableItems availableItems) {
        log.warn("Fallback 스트리밍 생성: {}", naturalLanguageQuery);

        return Flux.create(sink -> {
            try {
                // 분석 과정 시뮬레이션
                sink.next(ServerSentEvent.<String>builder()
                        .data("AI가 요청을 분석하고 있습니다...")
                        .build());

                // 짧은 지연 후 다음 단계
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
                            // 기본 JSON 응답 생성
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