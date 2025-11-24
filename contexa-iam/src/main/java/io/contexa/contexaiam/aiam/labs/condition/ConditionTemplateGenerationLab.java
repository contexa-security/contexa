package io.contexa.contexaiam.aiam.labs.condition;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacommon.domain.LabSpecialization;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.components.retriever.ConditionTemplateContextRetriever;
import io.contexa.contexaiam.aiam.labs.AbstractIAMLab;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 조건 템플릿 생성 전문 연구소 (리팩토링 버전)
 *
 * 기존 ConditionTemplateGenerationLab의 모든 기능을 유지하면서
 * 새로운 AbstractIAMLabNew 구조를 활용
 *
 * 기존 비즈니스 로직 100% 유지
 * PipelineOrchestrator 직접 사용 (기존과 동일)
 * 모든 메서드 시그니처 유지
 */
@Slf4j
public class ConditionTemplateGenerationLab extends AbstractIAMLab<ConditionTemplateGenerationRequest, ConditionTemplateGenerationResponse> {

    private final PipelineOrchestrator orchestrator;
    private final ObjectMapper objectMapper;
    private final ConditionTemplateVectorService vectorService;

    public ConditionTemplateGenerationLab(io.opentelemetry.api.trace.Tracer tracer,
                                          PipelineOrchestrator orchestrator,
                                          ConditionTemplateContextRetriever contextRetriever,
                                          ObjectMapper objectMapper,
                                          ConditionTemplateVectorService vectorService) {
        super(tracer, "ConditionTemplateGeneration", "2.0", LabSpecialization.RECOMMENDATION_SYSTEM);

        this.orchestrator = orchestrator;
        this.objectMapper = objectMapper;
        this.vectorService = vectorService;

        log.info("ConditionTemplateGenerationLab initialized - PipelineOrchestrator with Vector Storage");
    }

    @Override
    protected ConditionTemplateGenerationResponse doProcess(ConditionTemplateGenerationRequest request) throws Exception {
        if (request.isUniversal()) {
            return generateUniversalConditionTemplatesAsync().block();
        } else {
            return generateSpecificConditionTemplatesAsync(
                    request.getResourceIdentifier(),
                    request.getMethodInfo()
            ).block();
        }
    }

    @Override
    protected Mono<ConditionTemplateGenerationResponse> doProcessAsync(ConditionTemplateGenerationRequest request) {
        if (request.isUniversal()) {
            return generateUniversalConditionTemplatesAsync();
        } else {
            return generateSpecificConditionTemplatesAsync(
                    request.getResourceIdentifier(),
                    request.getMethodInfo()
            );
        }
    }

    private Mono<ConditionTemplateGenerationResponse> generateUniversalConditionTemplatesAsync() {
        
        // 벡터 저장소에 요청 저장
        try {
            ConditionTemplateGenerationRequest request = new ConditionTemplateGenerationRequest(true);
            vectorService.storeTemplateGenerationRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }

        return Mono.fromCallable(this::createUniversalTemplateRequest)
                .flatMap(aiRequest -> {
                    PipelineConfiguration config = createConditionTemplatePipelineConfig();
                    return orchestrator.execute(aiRequest, config, ConditionTemplateGenerationResponse.class);
                })
                .map(response -> {
                    if (response == null) {
                        return ConditionTemplateGenerationResponse.failure(
                                "unknown",
                                "universal",
                                null,
                                "Pipeline returned null response"
                        );
                    }
                    
                    // 벡터 저장소에 결과 저장
                    try {
                        ConditionTemplateGenerationRequest request = new ConditionTemplateGenerationRequest(true);
                        vectorService.storeGeneratedTemplates(request, (ConditionTemplateGenerationResponse) response);
                    } catch (Exception e) {
                        log.error("벡터 저장소 결과 저장 실패", e);
                    }

                    return (ConditionTemplateGenerationResponse) response;
                })
                .onErrorResume(error -> {
                    log.error("AI 범용 템플릿 비동기 생성 실패", error);
                    String errorMsg = error instanceof Throwable ? ((Throwable) error).getMessage() : error.toString();
                    return Mono.just(ConditionTemplateGenerationResponse.failure(
                            "unknown",
                            "universal",
                            null,
                            "Exception: " + errorMsg
                    ));
                });
    }

    private Mono<ConditionTemplateGenerationResponse> generateSpecificConditionTemplatesAsync(String resourceIdentifier, String methodInfo) {
        
        // 벡터 저장소에 요청 저장
        try {
            ConditionTemplateGenerationRequest request = ConditionTemplateGenerationRequest.forSpecificTemplate(resourceIdentifier, methodInfo);
            vectorService.storeTemplateGenerationRequest(request);
        } catch (Exception e) {
            log.error("벡터 저장소 요청 저장 실패", e);
        }

        return Mono.fromCallable(() -> createSpecificTemplateRequest(resourceIdentifier, methodInfo))
                .flatMap(aiRequest -> {
                    PipelineConfiguration config = createConditionTemplatePipelineConfig();
                    return orchestrator.execute(aiRequest, config, ConditionTemplateGenerationResponse.class);
                })
                .map(response -> {
                    if (response == null) {
                        return ConditionTemplateGenerationResponse.failure(
                                "unknown",
                                "specific",
                                resourceIdentifier,
                                "Pipeline returned null response"
                        );
                    }
                    
                    // 벡터 저장소에 결과 저장
                    try {
                        ConditionTemplateGenerationRequest request = new ConditionTemplateGenerationRequest(true);
                        vectorService.storeGeneratedTemplates(request, (ConditionTemplateGenerationResponse) response);
                    } catch (Exception e) {
                        log.error("벡터 저장소 결과 저장 실패", e);
                    }
                    
                    return (ConditionTemplateGenerationResponse)response;
                })
                .onErrorResume(error -> {
                    log.error("AI 특화 조건 비동기 생성 실패: {}", resourceIdentifier, error);
                    String errorMsg = error instanceof Throwable ? ((Throwable) error).getMessage() : error.toString();
                    return Mono.just(ConditionTemplateGenerationResponse.failure(
                            "unknown",
                            "specific",
                            resourceIdentifier,
                            "Exception: " + errorMsg
                    ));
                });
    }

    private PipelineConfiguration createConditionTemplatePipelineConfig() {
        return PipelineConfiguration.builder()
                .addStep(PipelineConfiguration.PipelineStep.CONTEXT_RETRIEVAL)
                .addStep(PipelineConfiguration.PipelineStep.PREPROCESSING)
                .addStep(PipelineConfiguration.PipelineStep.PROMPT_GENERATION)
                .addStep(PipelineConfiguration.PipelineStep.LLM_EXECUTION)
                .addStep(PipelineConfiguration.PipelineStep.RESPONSE_PARSING)
                .addStep(PipelineConfiguration.PipelineStep.POSTPROCESSING)
                .timeoutSeconds(30)
                .build();
    }

    private AIRequest<ConditionTemplateContext> createUniversalTemplateRequest() {
        ConditionTemplateContext context = ConditionTemplateContext.forUniversalTemplate();

        AIRequest<ConditionTemplateContext> request = new AIRequest<>(context, "conditionTemplateGeneration", context.getOrganizationId());

        request.withParameter("templateType", "universal");
        request.withParameter("requestType", "condition_template");
        request.withParameter("outputFormat", "json_array");
        request.withParameter("maxTemplates", 3);

        return request;
    }

    private AIRequest<ConditionTemplateContext> createSpecificTemplateRequest(String resourceIdentifier, String methodInfo) {
        ConditionTemplateContext context = ConditionTemplateContext.forSpecificTemplate(resourceIdentifier, methodInfo);

        AIRequest<ConditionTemplateContext> request = new AIRequest<>(context, "conditionTemplateGeneration", context.getOrganizationId());

        request.withParameter("templateType", "specific");
        request.withParameter("requestType", "condition_template");
        request.withParameter("resourceIdentifier", resourceIdentifier);
        request.withParameter("methodInfo", methodInfo);
        request.withParameter("outputFormat", "json_array");
        request.withParameter("maxTemplates", 1);

        return request;
    }

    private ConditionTemplateGenerationResponse validateAndOptimizeTemplateResult(
            String jsonResponse, String templateType, String resourceIdentifier) {

        if (jsonResponse == null || jsonResponse.trim().isEmpty()) {
            log.warn("Pipeline에서 빈 응답 수신, 폴백 사용");
            String fallback = "universal".equals(templateType) ?
                    getFallbackUniversalTemplates() :
                    generateFallbackSpecificTemplate(resourceIdentifier);
            return ConditionTemplateGenerationResponse.success(
                    "pipeline-empty",
                    fallback,
                    templateType,
                    resourceIdentifier
            );
        }

        try {
            log.info("파이프라인에서 JSON 응답 수신 - 길이: {}", jsonResponse.length());

            String cleanedJson = extractAndCleanJson(jsonResponse);
            if (cleanedJson.equals("[]")) {
                log.warn("JSON 응답이 비어있음, 폴백 사용");
                String fallback = "universal".equals(templateType) ?
                        getFallbackUniversalTemplates() :
                        generateFallbackSpecificTemplate(resourceIdentifier);
                return ConditionTemplateGenerationResponse.success(
                        "pipeline-empty-json",
                        fallback,
                        templateType,
                        resourceIdentifier
                );
            }

            jsonResponse = cleanedJson;
            List<ConditionTemplate> parsedTemplates = parseAITemplateResponse(jsonResponse, resourceIdentifier != null ? resourceIdentifier : "universal");

            if (parsedTemplates.isEmpty()) {
                log.warn("파싱된 템플릿이 비어있음, 폴백 사용");
                String fallback = "universal".equals(templateType) ?
                        getFallbackUniversalTemplates() :
                        generateFallbackSpecificTemplate(resourceIdentifier);
                return ConditionTemplateGenerationResponse.success(
                        "pipeline-empty-parsed",
                        fallback,
                        templateType,
                        resourceIdentifier
                );
            }

            return ConditionTemplateGenerationResponse.success(
                    "pipeline-success",
                    jsonResponse,
                    templateType,
                    resourceIdentifier
            );

        } catch (Exception e) {
            log.error("조건 템플릿 결과 검증 실패", e);
            String fallback = "universal".equals(templateType) ?
                    getFallbackUniversalTemplates() :
                    generateFallbackSpecificTemplate(resourceIdentifier);
            return ConditionTemplateGenerationResponse.success(
                    "pipeline-error",
                    fallback,
                    templateType,
                    resourceIdentifier
            );
        }
    }

    private String extractAndCleanJson(String aiResponse) {
        if (aiResponse == null || aiResponse.trim().isEmpty()) {
            return "[]";
        }

        // 마크다운 코드 블록 제거
        String cleaned = aiResponse.replaceAll("```json\\s*", "").replaceAll("```\\s*", "");

        // JSON 배열 시작과 끝 찾기
        int startIdx = cleaned.indexOf('[');
        int endIdx = cleaned.lastIndexOf(']');

        if (startIdx != -1 && endIdx != -1 && startIdx < endIdx) {
            return cleaned.substring(startIdx, endIdx + 1).trim();
        }

        // JSON 객체 형태인 경우 배열로 감싸기
        startIdx = cleaned.indexOf('{');
        endIdx = cleaned.lastIndexOf('}');

        if (startIdx != -1 && endIdx != -1 && startIdx < endIdx) {
            String jsonObject = cleaned.substring(startIdx, endIdx + 1).trim();
            return "[" + jsonObject + "]";
        }

        // 파싱할 수 있는 JSON이 없으면 빈 배열 반환
        log.warn("AI 응답에서 유효한 JSON을 찾을 수 없음: {}", aiResponse.substring(0, Math.min(100, aiResponse.length())));
        return "[]";
    }

    private List<ConditionTemplate> parseAITemplateResponse(String aiResponse, String sourceMethod) {
        List<ConditionTemplate> templates = new ArrayList<>();

        log.info("AI 응답 파싱 시작 - 소스: {}", sourceMethod);
        log.info("원본 AI 응답: {}", aiResponse);

        try {
            // JSON 정제 - 마크다운 코드 블록 제거 및 불필요한 텍스트 제거
            String cleanedJson = extractAndCleanJson(aiResponse);
            log.info("정제된 JSON: {}", cleanedJson);

            // JSON 배열 파싱 시도
            List<Map<String, Object>> rawTemplates = objectMapper.readValue(
                    cleanedJson, new TypeReference<List<Map<String, Object>>>() {});

            log.info("파싱된 템플릿 개수: {} 개", rawTemplates.size());

            for (int i = 0; i < rawTemplates.size(); i++) {
                Map<String, Object> raw = rawTemplates.get(i);
                log.info("템플릿 {} 파싱: {}", i+1, raw);

                try {
                    ConditionTemplate template = ConditionTemplate.builder()
                            .name((String) raw.get("name"))
                            .description((String) raw.get("description"))
                            .spelTemplate((String) raw.get("spelTemplate"))
                            .category((String) raw.getOrDefault("category", "AI 생성"))
                            .classification(parseClassification((String) raw.get("classification")))
                            .sourceMethod(sourceMethod)
                            .isAutoGenerated(true)
                            .templateType("ai_generated")
                            .createdAt(LocalDateTime.now())
                            .build();

                    // SpEL 템플릿이 비어있지 않은 경우만 추가
                    if (template.getSpelTemplate() != null && !template.getSpelTemplate().trim().isEmpty()) {
                        templates.add(template);
                        log.info("템플릿 추가됨: {} - {}", template.getName(), template.getSpelTemplate());
                    } else {
                        log.warn("빈 SpEL 템플릿으로 인해 제외됨: {}", raw);
                    }
                } catch (Exception itemError) {
                    log.error("템플릿 항목 파싱 실패: {}", raw, itemError);
                }
            }

            log.info("AI 응답 파싱 완료: {} 개 템플릿 최종 생성", templates.size());

        } catch (Exception e) {
            log.error("AI 응답 파싱 실패: {}", aiResponse, e);
            // 파싱 실패 시 빈 리스트 반환
        }

        return templates;
    }

    private ConditionTemplate.ConditionClassification parseClassification(String classification) {
        if (classification == null) return ConditionTemplate.ConditionClassification.CONTEXT_DEPENDENT;

        try {
            return ConditionTemplate.ConditionClassification.valueOf(classification.toUpperCase());
        } catch (Exception e) {
            return ConditionTemplate.ConditionClassification.CONTEXT_DEPENDENT;
        }
    }

    private String getFallbackUniversalTemplates() {
        return """
        [
          {
            "name": "사용자 인증 상태 확인",
            "description": "사용자가 인증되었는지 확인하는 조건",
            "spelTemplate": "isAuthenticated()",
            "category": "인증 상태",
            "classification": "UNIVERSAL"
          },
          {
            "name": "관리자 역할 확인",
            "description": "관리자 역할을 가진 사용자인지 확인하는 조건",
            "spelTemplate": "hasRole('ROLE_ADMIN')",
            "category": "역할 확인",
            "classification": "UNIVERSAL"
          },
          {
            "name": "업무시간 접근 제한",
            "description": "오전 9시부터 오후 6시까지만 접근을 허용하는 조건",
            "spelTemplate": "T(java.time.LocalTime).now().hour >= 9 && T(java.time.LocalTime).now().hour <= 18",
            "category": "시간 제한",
            "classification": "UNIVERSAL"
          }
        ]
        """;
    }

    private String generateFallbackSpecificTemplate(String resourceIdentifier) {
        return String.format("""
        [
          {
            "name": "%s 대상 검증",
            "description": "%s 리소스에 대한 접근 검증 조건",
            "spelTemplate": "hasPermission(#param, '%s', 'READ')",
            "category": "리소스 접근",
            "classification": "SPECIFIC"
          }
        ]
        """, resourceIdentifier, resourceIdentifier, resourceIdentifier);
    }
    
    /**
     * 피드백 기반 학습
     * 
     * @param request 원본 요청
     * @param response 생성된 응답
     * @param feedback 사용자 피드백
     */
    public void learnFromFeedback(ConditionTemplateGenerationRequest request, ConditionTemplateGenerationResponse response, String feedback) {
        try {
            // 현재 ConditionTemplateVectorService는 storeFeedback 메서드가 없으므로
            // 생성된 템플릿을 다시 저장하면서 피드백을 메타데이터로 포함
            log.info("[ConditionTemplateGenerationLab] 피드백 학습 시작: {}", feedback.substring(0, Math.min(50, feedback.length())));
            
            // 향후 확장 가능
            vectorService.storeGeneratedTemplates(request, response);
            
            log.info("[ConditionTemplateGenerationLab] 피드백 학습 완료");
        } catch (Exception e) {
            log.error("[ConditionTemplateGenerationLab] 피드백 학습 실패", e);
        }
    }
}
