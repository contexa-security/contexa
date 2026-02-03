package io.contexa.contexaiam.aiam.labs.policy;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.streaming.StreamingProtocol;
import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.response.IAMResponse;
import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.labs.data.IAMDataCollectionService;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexacommon.enums.SecurityLevel;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import io.contexa.contexaiam.domain.dto.AiGeneratedPolicyDraftDto;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
public class AdvancedPolicyGenerationLab extends AbstractIAMLab<PolicyGenerationRequest,PolicyResponse> {

    private final PipelineOrchestrator orchestrator;
    private final IAMDataCollectionService dataCollectionService;
    private final PolicyGenerationVectorService vectorService;

    public AdvancedPolicyGenerationLab(PipelineOrchestrator orchestrator,
                                       IAMDataCollectionService dataCollectionService,
                                       PolicyGenerationVectorService vectorService) {
        super("AdvancedPolicyGenerationLab", "2.0.0", LabSpecialization.POLICY_GENERATION);
        this.orchestrator = orchestrator;
        this.dataCollectionService = dataCollectionService;
        this.vectorService = vectorService;
    }

    @Override
    public boolean supportsStreaming() {
        return true;
    }

    @Override
    protected PolicyResponse doProcess(PolicyGenerationRequest request) throws Exception {
        AiGeneratedPolicyDraftDto policyDraft = generatePolicyFromTextSync(
                request.getNaturalLanguageQuery(),
                request.getAvailableItems()
        );

        return convertDtoToPolicyResponse(policyDraft, "sync-request-id");
    }

    @Override
    protected Mono<PolicyResponse> doProcessAsync(PolicyGenerationRequest request) {
        return generatePolicyFromTextAsync(
                request.getNaturalLanguageQuery(),
                request.getAvailableItems()
        ).map(policyDraft -> convertDtoToPolicyResponse(policyDraft, "async-request-id"));
    }

    @Override
    protected Flux<String> doProcessStream(PolicyGenerationRequest request) {
        return generateRealPolicyFromTextStream(
                request.getNaturalLanguageQuery(),
                request.getAvailableItems()
        );
    }

    private Mono<AiGeneratedPolicyDraftDto> generatePolicyFromTextAsync(String naturalLanguageQuery,
                                                                       PolicyGenerationItem.AvailableItems availableItems) {

        PolicyGenerationRequest request = null;
        try {
            request = new PolicyGenerationRequest(naturalLanguageQuery, availableItems);
            vectorService.storePolicyGenerationRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }

        PolicyGenerationRequest finalRequest = request;
        return Mono.fromCallable(() -> createPolicyGenerationRequest(naturalLanguageQuery, availableItems))
                .flatMap(aiRequest -> {
                                        return orchestrator.execute(aiRequest, PolicyResponse.class);
                })
                .map(response -> {
                    if (response == null) {
                        log.warn("비동기 Pipeline에서 null 응답 수신, fallback 생성");
                        return createFallbackPolicyData(naturalLanguageQuery);
                    }

                    PolicyResponse policyResponse = (PolicyResponse) response;

                    try {
                        AiGeneratedPolicyDraftDto policyDto = convertPolicyResponseToDto(policyResponse, naturalLanguageQuery);
                        vectorService.storeGeneratedPolicy(finalRequest, policyDto);
                        return policyDto;
                    } catch (Exception e) {
                        log.error("벡터 저장소 정책 저장 실패", e);
                        return convertPolicyResponseToDto(policyResponse, naturalLanguageQuery);
                    }
                })
                .doOnError(error -> {
                    if (error instanceof Throwable) {
                        Throwable throwable = (Throwable) error;
                        log.error("[DIAGNOSIS] AI 정책 진단 생성 실패: {}", throwable.getMessage(), throwable);
                    }
                })
                .onErrorResume(error -> {
                    log.error("AI 정책 비동기 생성 실패", error);
                    return Mono.just(createFallbackPolicyData(naturalLanguageQuery));
                });
    }

    private Flux<String> generateRealPolicyFromTextStream(String naturalLanguageQuery,
                                                         PolicyGenerationItem.AvailableItems availableItems) {
        
        try {
            
            AIRequest<PolicyContext> aiRequest = createPolicyGenerationStreamingRequest(naturalLanguageQuery, availableItems);

            Flux<String> streamingFlux = orchestrator.executeStream(aiRequest);
            return streamingFlux
                    .doOnSubscribe(subscription -> { })
                    .doOnNext(chunk -> {
                        String chunkStr = chunk != null ? chunk.toString() : "";

                    })
                    .map(this::cleanStreamingChunk)
                    .concatWith(Mono.just("[DONE]"))
                    .doOnComplete(() -> {
                                            })
                    .doOnError(error -> {
                        log.error("실제 스트리밍 중 오류 발생", error);
                    })
                    .onErrorResume(error -> {
                        log.error("실제 스트리밍 실패, 에러 메시지 반환", error);
                        return Flux.just("ERROR: AI 서비스 연결 실패: " + error.getMessage(), "[DONE]");
                    });

        } catch (Exception e) {
            log.error("실제 AI 스트리밍 초기화 실패", e);
            return Flux.just("ERROR: 실제 스트리밍 초기화 실패: " + e.getMessage(), "[DONE]");
        }
    }

    private AiGeneratedPolicyDraftDto generatePolicyFromTextSync(String naturalLanguageQuery,
                                                                 PolicyGenerationItem.AvailableItems availableItems) {
        try {
            return generatePolicyFromTextAsync(naturalLanguageQuery, availableItems).block();
        } catch (Exception e) {
            log.error("동기 정책 생성 실패", e);
            return createFallbackPolicyData(naturalLanguageQuery);
        }
    }

    private PolicyResponse convertDtoToPolicyResponse(AiGeneratedPolicyDraftDto dto, String requestId) {
        PolicyResponse response = new PolicyResponse(requestId, IAMResponse.ExecutionStatus.SUCCESS);
        response.setPolicyData(dto.policyData());
        response.setRoleIdToNameMap(dto.roleIdToNameMap());
        response.setPermissionIdToNameMap(dto.permissionIdToNameMap());
        response.setConditionIdToNameMap(dto.conditionIdToNameMap());
        return response;
    }

    private AIRequest<PolicyContext> createPolicyGenerationStreamingRequest(String naturalLanguageQuery,
                                                                            PolicyGenerationItem.AvailableItems availableItems) {

        if(availableItems == null){
             availableItems = dataCollectionService.policyCollectData();
        }

        PolicyContext context = new PolicyContext.Builder(SecurityLevel.STANDARD, AuditRequirement.BASIC)
                .withNaturalLanguageQuery(naturalLanguageQuery).build();

        String orgId = context.getOrganizationId();
        if (orgId == null || orgId.trim().isEmpty()) {
            orgId = "default-org";
        }

        AIRequest<PolicyContext> request = new AIRequest<>(context, "policyGenerationStreaming", orgId);

        if (naturalLanguageQuery != null) {
            request.withParameter("naturalLanguageQuery", naturalLanguageQuery);
        }
        if (availableItems != null) {
            request.withParameter("availableItems", availableItems);
        }
        request.withParameter("requestType", "policy_generation_streaming");
        request.withParameter("outputFormat", "streaming_json");
        request.withParameter("enableRealTimeAnalysis", true);

        if (availableItems != null) {
            request.withParameter("systemMetadata", buildSystemMetadataFromAvailableItems(availableItems));
                    }

        return request;
    }

    private String buildSystemMetadataFromAvailableItems(PolicyGenerationItem.AvailableItems availableItems) {
        StringBuilder metadata = new StringBuilder();
        metadata.append("현재 사용 가능한 항목들 (반드시 이 ID들만 사용하세요):\n\n");

        if (availableItems.roles() != null && !availableItems.roles().isEmpty()) {
            metadata.append("사용 가능한 역할:\n");
            availableItems.roles().forEach(role ->
                    metadata.append(String.format("- ID: %d, 이름: %s, 설명: %s\n",
                            role.id(), role.name(), role.description() != null ? role.description() : "")));
        } else {
            metadata.append("사용 가능한 역할: 없음\n");
        }

        if (availableItems.permissions() != null && !availableItems.permissions().isEmpty()) {
            metadata.append("\n🔑 사용 가능한 권한:\n");
            availableItems.permissions().forEach(perm ->
                    metadata.append(String.format("- ID: %d, 이름: %s, 설명: %s\n",
                            perm.id(), perm.name(), perm.description() != null ? perm.description() : "")));
        } else {
            metadata.append("\n🔑 사용 가능한 권한: 없음\n");
        }

        if (availableItems.conditions() != null && !availableItems.conditions().isEmpty()) {
            metadata.append("\n⏰ 사용 가능한 조건 템플릿:\n");
            availableItems.conditions().forEach(cond ->
                    metadata.append(String.format("- ID: %d, 이름: %s, 설명: %s, 호환가능: %s\n",
                            cond.id(), cond.name(),
                            cond.description() != null ? cond.description() : "",
                            cond.isCompatible() != null ? cond.isCompatible() : true)));
        } else {
            metadata.append("\n⏰ 사용 가능한 조건 템플릿: 없음\n");
        }

        metadata.append("\n경고: 위에 나열된 ID들 외의 다른 ID는 절대 사용하지 마세요. 존재하지 않는 ID를 사용하면 시스템 오류가 발생합니다.\n");

        return metadata.toString();
    }

    private String cleanStreamingChunk(String chunk) {
        if (chunk == null || chunk.isEmpty()) {
            return "";
        }

        try {
            byte[] bytes = chunk.getBytes(StandardCharsets.UTF_8);
            String decoded = new String(bytes, StandardCharsets.UTF_8);
            String cleaned = decoded.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "");
            return cleaned;
        } catch (Exception e) {
            log.warn("스트리밍 청크 정제 실패: {}", e.getMessage());
            return chunk;
        }
    }

    private AIRequest<PolicyContext> createPolicyGenerationRequest(String naturalLanguageQuery,
                                                                   PolicyGenerationItem.AvailableItems availableItems) {
        PolicyContext context = new PolicyContext.Builder(
                SecurityLevel.STANDARD,
                AuditRequirement.BASIC
        ).withNaturalLanguageQuery(naturalLanguageQuery).build();

        String orgId = context.getOrganizationId();
        if (orgId == null || orgId.trim().isEmpty()) {
            orgId = "default-org";
        }

        AIRequest<PolicyContext> request = new AIRequest<>(context, "policyGeneration", orgId);

        if (naturalLanguageQuery != null) {
            request.withParameter("naturalLanguageQuery", naturalLanguageQuery);
        }
        if (availableItems != null) {
            request.withParameter("availableItems", availableItems);
        }
        request.withParameter("requestType", "policy_generation");
        request.withParameter("outputFormat", "json_object");

        return request;
    }

    private AiGeneratedPolicyDraftDto convertPolicyResponseToDto(PolicyResponse policyResponse, String naturalLanguageQuery) {
        if (policyResponse == null) {
            log.warn("PolicyResponse가 null, fallback 생성");
            return createFallbackPolicyData(naturalLanguageQuery);
        }

        if (policyResponse.getPolicyData() != null) {
                        return new AiGeneratedPolicyDraftDto(
                    policyResponse.getPolicyData(),
                    policyResponse.getRoleIdToNameMap(),
                    policyResponse.getPermissionIdToNameMap(),
                    policyResponse.getConditionIdToNameMap()
            );
        }

        if (policyResponse.getGeneratedPolicy() != null && !policyResponse.getGeneratedPolicy().trim().isEmpty()) {
                        return validateAndOptimizePolicyResult(policyResponse.getGeneratedPolicy(), naturalLanguageQuery);
        }

        log.warn("PolicyResponse에 유효한 데이터가 없음, fallback 생성");
        return createFallbackPolicyData(naturalLanguageQuery);
    }

    private AiGeneratedPolicyDraftDto validateAndOptimizePolicyResult(String jsonResponse, String naturalLanguageQuery) {
        if (jsonResponse == null || jsonResponse.trim().isEmpty()) {
            log.warn("빈 JSON 응답, fallback 사용");
            return createFallbackPolicyData(naturalLanguageQuery);
        }

        try {
            
            if (jsonResponse.contains("{") && jsonResponse.contains("}")) {
                            }

            return createFallbackPolicyData(naturalLanguageQuery);

        } catch (Exception e) {
            log.error("JSON 검증 실패, fallback 사용", e);
            return createFallbackPolicyData(naturalLanguageQuery);
        }
    }

    private AiGeneratedPolicyDraftDto createFallbackPolicyData(String naturalLanguageQuery) {
        log.warn("Fallback 정책 데이터 생성: {}", naturalLanguageQuery);

        BusinessPolicyDto fallbackPolicy = new BusinessPolicyDto();
        fallbackPolicy.setPolicyName("AI 생성 정책 (Fallback)");
        fallbackPolicy.setDescription("요청: " + (naturalLanguageQuery != null ? naturalLanguageQuery : "알 수 없음"));

        return new AiGeneratedPolicyDraftDto(
                fallbackPolicy,
                Map.of(),
                Map.of(),
                Map.of()
        );
    }

    private String convertToStreamingJson(AiGeneratedPolicyDraftDto result) {
        try {
            StringBuilder json = new StringBuilder();
            json.append(StreamingProtocol.JSON_START_MARKER).append("\n");
            json.append("{\n");
            json.append(String.format("  \"policyName\": \"%s\",\n",
                    result.policyData().getPolicyName() != null ? result.policyData().getPolicyName() : "AI 생성 정책"));
            json.append(String.format("  \"description\": \"%s\",\n",
                    result.policyData().getDescription() != null ? result.policyData().getDescription() : "AI가 생성한 정책"));
            json.append("  \"status\": \"completed\"\n");
            json.append("}\n");
            json.append(StreamingProtocol.JSON_END_MARKER);

            return json.toString();
        } catch (Exception e) {
            log.error("스트리밍 JSON 변환 실패", e);
            return "ERROR: JSON 변환 실패: " + e.getMessage();
        }
    }

    private AiGeneratedPolicyDraftDto parseFullRawResponseToDto(String jsonData, String naturalLanguageQuery) {
        if (jsonData == null || jsonData.trim().isEmpty()) {
            log.warn("빈 jsonData, fallback 생성");
            return createFallbackPolicyData(naturalLanguageQuery);
        }

        try {

            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

            Map<String, Object> responseMap = mapper.readValue(jsonData, Map.class);

            Map<String, Object> policyDataMap = (Map<String, Object>) responseMap.get("policyData");
            
            if (policyDataMap == null) {
                log.warn("policyData가 null, fallback 생성");
                return createFallbackPolicyData(naturalLanguageQuery);
            }

            BusinessPolicyDto policyData = new BusinessPolicyDto();
            policyData.setPolicyName((String) policyDataMap.get("policyName"));
            policyData.setDescription((String) policyDataMap.get("description"));

            Set<Long> roleIds = extractRoleIds(policyDataMap);
            Set<Long> permissionIds = extractPermissionIds(policyDataMap);
            
            policyData.setRoleIds(roleIds);
            policyData.setPermissionIds(permissionIds);
            policyData.setEffect(Policy.Effect.ALLOW);
            policyData.setConditional(true);
            policyData.setConditions(new HashMap<>());

            Map<String, String> roleIdToNameMap = (Map<String, String>) responseMap.get("roleIdToNameMap");
            Map<String, String> permissionIdToNameMap = (Map<String, String>) responseMap.get("permissionIdToNameMap");
            Map<String, String> conditionIdToNameMap = (Map<String, String>) responseMap.get("conditionIdToNameMap");

            return new AiGeneratedPolicyDraftDto(
                    policyData,
                    roleIdToNameMap != null ? roleIdToNameMap : new HashMap<>(),
                    permissionIdToNameMap != null ? permissionIdToNameMap : new HashMap<>(),
                    conditionIdToNameMap != null ? conditionIdToNameMap : new HashMap<>()
            );

        } catch (Exception e) {
            log.error("[DIAGNOSIS] fullRawResponse 파싱 실패", e);
            return createFallbackPolicyData(naturalLanguageQuery);
        }
    }

    private Set<Long> extractRoleIds(Map<String, Object> policyDataMap) {
        Set<Long> roleIds = new HashSet<>();
        
        Object rolesObj = policyDataMap.get("roles");
        if (rolesObj instanceof List) {
            List<Object> rolesList = (List<Object>) rolesObj;
            for (Object roleObj : rolesList) {
                if (roleObj instanceof Map) {
                    Map<String, Object> roleMap = (Map<String, Object>) roleObj;
                    Object roleIdObj = roleMap.get("roleId");
                    if (roleIdObj != null) {
                        try {
                            Long roleId = Long.valueOf(roleIdObj.toString());
                            roleIds.add(roleId);
                        } catch (NumberFormatException e) {
                            log.warn("역할 ID 변환 실패: {}", roleIdObj);
                        }
                    }
                }
            }
        }
        
        return roleIds;
    }

    private Set<Long> extractPermissionIds(Map<String, Object> policyDataMap) {
        Set<Long> permissionIds = new HashSet<>();

        Object rolesObj = policyDataMap.get("roles");
        if (rolesObj instanceof List) {
            List<Object> rolesList = (List<Object>) rolesObj;
            for (Object roleObj : rolesList) {
                if (roleObj instanceof Map) {
                    Map<String, Object> roleMap = (Map<String, Object>) roleObj;
                    Object permissionsObj = roleMap.get("permissions");
                    if (permissionsObj instanceof List) {
                        List<String> permissionsList = (List<String>) permissionsObj;
                        for (String permission : permissionsList) {
                            
                            Long permissionId = (long) Math.abs(permission.hashCode()) % 10000;
                            permissionIds.add(permissionId);
                        }
                    }
                }
            }
        }
        
        return permissionIds;
    }

    public void learnFromFeedback(PolicyGenerationRequest request, PolicyResponse response, String feedback) {
        try {

            AiGeneratedPolicyDraftDto policyDto = convertPolicyResponseToDto(response, request.getNaturalLanguageQuery());
            vectorService.storeGeneratedPolicy(request, policyDto);
            
                    } catch (Exception e) {
            log.error("[AdvancedPolicyGenerationLab] 피드백 학습 실패", e);
        }
    }
}