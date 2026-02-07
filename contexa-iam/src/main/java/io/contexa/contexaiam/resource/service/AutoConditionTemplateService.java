package io.contexa.contexaiam.resource.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Slf4j
public class AutoConditionTemplateService {

    private final ConditionTemplateRepository conditionTemplateRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final AICoreOperations<ConditionTemplateContext> aiNativeProcessor;
    private final ObjectMapper objectMapper;

    @Transactional
    public List<ConditionTemplate> saveDedupedTemplates(List<ConditionTemplate> templates) {

        List<ConditionTemplate> allExistingTemplates = conditionTemplateRepository.findAll();

        Set<String> existingNames = allExistingTemplates.stream()
                .map(ConditionTemplate::getName)
                .collect(Collectors.toSet());

        Set<String> existingSpelTemplates = allExistingTemplates.stream()
                .map(ConditionTemplate::getSpelTemplate)
                .collect(Collectors.toSet());

        Set<String> processingNames = new HashSet<>();

        List<ConditionTemplate> newTemplates = templates.stream()
                .filter(template -> {

                    if (existingSpelTemplates.contains(template.getSpelTemplate())) {
                        return false;
                    }

                    String originalName = template.getName();
                    String uniqueName = makeUniqueName(originalName, existingNames, processingNames);

                    if (!originalName.equals(uniqueName)) {
                        template.setName(uniqueName);
                    }

                    processingNames.add(uniqueName);
                    existingNames.add(uniqueName);

                    return true;
                })
                .collect(Collectors.toList());

        return newTemplates.isEmpty() ? new ArrayList<>() : conditionTemplateRepository.saveAll(newTemplates);
    }

    private String makeUniqueName(String baseName, Set<String> existingNames, Set<String> processingNames) {
        if (!existingNames.contains(baseName) && !processingNames.contains(baseName)) {
            return baseName;
        }

        for (int i = 2; i <= 100; i++) {
            String candidateName = baseName + " (" + i + ")";
            if (!existingNames.contains(candidateName) && !processingNames.contains(candidateName)) {
                return candidateName;
            }
        }

        String timestampName = baseName + " (" + System.currentTimeMillis() % 10000 + ")";
        log.warn("고유 이름 생성을 위해 타임스탬프 사용: {}", timestampName);
        return timestampName;
    }

    @Transactional
    public List<ConditionTemplate> generateConditionTemplates() {

        List<ManagedResource> methodResources = managedResourceRepository.findAll()
                .stream()
                .filter(resource -> resource.getResourceType() == ManagedResource.ResourceType.METHOD)
                .filter(resource -> resource.getStatus() != ManagedResource.Status.EXCLUDED)
                .toList();

        if (methodResources.isEmpty()) {
            log.warn("METHOD 타입 리소스가 없습니다. 조건 템플릿을 생성하지 않습니다.");
            return new ArrayList<>();
        }

        List<ConditionTemplate> templates = new ArrayList<>(generateAIUniversalTemplates());

        Set<String> processedMethodSignatures = new HashSet<>();
        int processedCount = 0;
        int skippedCount = 0;

        for (ManagedResource resource : methodResources) {
            try {

                String resourceKey = resource.getResourceIdentifier();

                if (processedMethodSignatures.contains(resourceKey)) {
                    log.warn("중복 리소스 건너뛰기: {}", resourceKey);
                    skippedCount++;
                    continue;
                }

                List<ConditionTemplate> methodTemplates = generateAISpecificTemplates(resource);
                templates.addAll(methodTemplates);
                processedMethodSignatures.add(resourceKey);
                processedCount++;

            } catch (Exception e) {
                log.warn("AI 메서드 분석 실패: {} - {}", resource.getResourceIdentifier(), e.getMessage());
                skippedCount++;
            }
        }

        return saveDedupedTemplates(templates);
    }

    private List<ConditionTemplate> generateAIUniversalTemplates() {

        String userPrompt = "서비스 레이어에서 정말 필요한 핵심 범용 조건 4-5개만 생성해주세요.";

        try {
            String aiResponse = callAI(userPrompt);
            return parseAITemplateResponse(aiResponse, "범용");
        } catch (Exception e) {
            log.error("AI 범용 템플릿 생성 실패", e);
            return generateFallbackUniversalTemplates();
        }
    }

    private List<ConditionTemplate> generateAISpecificTemplates(ManagedResource resource) {

        String parameterTypes = resource.getParameterTypes();
        log.warn("DEBUG - AutoConditionTemplateService 파라미터 체크: resourceIdentifier={}, parameterTypes='{}'",
                resource.getResourceIdentifier(), parameterTypes);

        if (parameterTypes == null || parameterTypes.trim().isEmpty() ||
                parameterTypes.equals("[]") || parameterTypes.equals("()")) {
            log.warn("AutoConditionTemplateService - 파라미터 없는 메서드 건너뛰기: {}", resource.getResourceIdentifier());
            return new ArrayList<>();
        }

        try {

            ConditionTemplateGenerationRequest request = ConditionTemplateGenerationRequest.forSpecificTemplate(
                    resource.getResourceIdentifier(), "AUTO_GENERATED");

            ConditionTemplateGenerationResponse response = aiNativeProcessor.process(request, ConditionTemplateGenerationResponse.class).block();

            if (response != null && response.hasTemplates()) {
                String templateResult = response.getTemplateResult();

                List<ConditionTemplate> templates = parseAITemplateResponse(templateResult, resource.getResourceIdentifier());

                if (templates.size() > 1) {
                    log.warn("AI가 {} 개 조건 생성했지만 첫 번째만 사용: {}", templates.size(), resource.getResourceIdentifier());
                    templates = List.of(templates.getFirst());
                }

                return templates;
            } else {
                log.warn("특화 조건 템플릿 응답이 비어있음");
                return new ArrayList<>();
            }

        } catch (Exception e) {
            log.warn("AI 특화 템플릿 생성 실패: {}", resource.getResourceIdentifier(), e);
            return new ArrayList<>();
        }
    }

    private String callAI(String userPrompt) {
        try {

            if (userPrompt.contains("범용") || userPrompt.contains("업무 환경에서 자주 사용되는")) {

                ConditionTemplateGenerationRequest request = ConditionTemplateGenerationRequest.forUniversalTemplate();

                ConditionTemplateGenerationResponse response = aiNativeProcessor.process(request, ConditionTemplateGenerationResponse.class).block();

                if (response != null && response.hasTemplates()) {
                    return response.getTemplateResult();
                } else {
                    log.warn("범용 조건 템플릿 응답이 비어있음");
                    return "[]";
                }

            } else {

                ConditionTemplateGenerationRequest request = ConditionTemplateGenerationRequest.forSpecificTemplate(
                        "METHOD", userPrompt);

                ConditionTemplateGenerationResponse response = aiNativeProcessor.process(request, ConditionTemplateGenerationResponse.class).block();

                if (response != null && response.hasTemplates()) {
                    return response.getTemplateResult();
                } else {
                    log.warn("특화 조건 템플릿 응답이 비어있음");
                    return "[]";
                }
            }

        } catch (Exception e) {
            log.error("AINativeIAMOperations 호출 실패", e);

            return "[]";
        }
    }

    private List<ConditionTemplate> parseAITemplateResponse(String aiResponse, String sourceMethod) {
        List<ConditionTemplate> templates = new ArrayList<>();

        try {

            String cleanedJson = extractAndCleanJson(aiResponse);
            List<Map<String, Object>> rawTemplates = objectMapper.readValue(cleanedJson, new TypeReference<>() {});

            for (Map<String, Object> raw : rawTemplates) {
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

                    if (template.getSpelTemplate() != null && !template.getSpelTemplate().trim().isEmpty()) {
                        templates.add(template);
                    } else {
                        log.warn("빈 SpEL 템플릿으로 인해 제외됨: {}", raw);
                    }
                } catch (Exception itemError) {
                    log.error("템플릿 항목 파싱 실패: {}", raw, itemError);
                }
            }

        } catch (Exception e) {
            log.error("AI 응답 파싱 실패: {}", aiResponse, e);

        }

        return templates;
    }

    private String extractAndCleanJson(String aiResponse) {
        if (aiResponse == null || aiResponse.trim().isEmpty()) {
            return "[]";
        }

        String cleaned = aiResponse.replaceAll("```json\\s*", "").replaceAll("```\\s*", "");

        int startIdx = cleaned.indexOf('[');
        int endIdx = cleaned.lastIndexOf(']');

        if (startIdx != -1 && endIdx != -1 && startIdx < endIdx) {
            return cleaned.substring(startIdx, endIdx + 1).trim();
        }

        startIdx = cleaned.indexOf('{');
        endIdx = cleaned.lastIndexOf('}');

        if (startIdx != -1 && endIdx != -1 && startIdx < endIdx) {
            String jsonObject = cleaned.substring(startIdx, endIdx + 1).trim();
            return "[" + jsonObject + "]";
        }

        log.warn("AI 응답에서 유효한 JSON을 찾을 수 없음: {}", aiResponse.substring(0, Math.min(100, aiResponse.length())));
        return "[]";
    }

    private ConditionTemplate.ConditionClassification parseClassification(String classification) {
        if (classification == null) return ConditionTemplate.ConditionClassification.CONTEXT_DEPENDENT;

        try {
            return ConditionTemplate.ConditionClassification.valueOf(classification.toUpperCase());
        } catch (Exception e) {
            return ConditionTemplate.ConditionClassification.CONTEXT_DEPENDENT;
        }
    }

    private List<ConditionTemplate> generateFallbackUniversalTemplates() {

        List<ConditionTemplate> templates = new ArrayList<>();

        templates.add(ConditionTemplate.builder()
                .name("객체 읽기 권한")
                .description("메서드가 반환하는 객체에 대한 읽기 권한 확인")
                .category("권한 기반")
                .classification(ConditionTemplate.ConditionClassification.CONTEXT_DEPENDENT)
                .spelTemplate("hasPermission(#returnObject, 'READ')")
                .sourceMethod("기본")
                .isAutoGenerated(true)
                .templateType("fallback")
                .createdAt(LocalDateTime.now())
                .build());

        templates.add(ConditionTemplate.builder()
                .name("인증 확인")
                .description("사용자가 인증되었는지 확인")
                .category("인증 기반")
                .classification(ConditionTemplate.ConditionClassification.UNIVERSAL)
                .spelTemplate("isAuthenticated()")
                .sourceMethod("기본")
                .isAutoGenerated(true)
                .templateType("fallback")
                .createdAt(LocalDateTime.now())
                .build());

        return templates;
    }
}