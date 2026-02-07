package io.contexa.contexaiam.resource.service;

import com.google.common.collect.Lists;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacore.std.operations.AICoreOperations;
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
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Slf4j
public class AutoConditionTemplateService {

    private final ConditionTemplateRepository conditionTemplateRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final AICoreOperations<ConditionTemplateContext> aiNativeProcessor;

    private static final int BATCH_SIZE = 10;

    @Transactional
    public List<ConditionTemplate> generateConditionTemplates() {

        List<ManagedResource> methodResources = managedResourceRepository.findByResourceType(ManagedResource.ResourceType.METHOD);

        if (methodResources.isEmpty()) {
            return new ArrayList<>();
        }

        List<ConditionTemplate> templates = new ArrayList<>(generateAIUniversalTemplates());

        List<ManagedResource> uniqueResources = methodResources.stream()
                .filter(resource -> {
                    String parameterTypes = resource.getParameterTypes();
                    return parameterTypes != null && !parameterTypes.trim().isEmpty()
                            && !parameterTypes.equals("[]") && !parameterTypes.equals("()");
                })
                .collect(Collectors.collectingAndThen(
                        Collectors.toMap(ManagedResource::getResourceIdentifier, Function.identity(), (a, b) -> a),
                        map -> new ArrayList<>(map.values())
                ));

        if (!uniqueResources.isEmpty()) {
            List<List<ManagedResource>> batches = Lists.partition(uniqueResources, BATCH_SIZE);

            List<CompletableFuture<List<ConditionTemplate>>> futures = batches.stream()
                    .map(batch -> CompletableFuture.supplyAsync(() -> processConditionBatch(batch)))
                    .toList();

            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

            for (CompletableFuture<List<ConditionTemplate>> future : futures) {
                try {
                    templates.addAll(future.join());
                } catch (Exception e) {
                    log.error("Condition batch processing failed", e);
                }
            }
        }

        return saveDedupedTemplates(templates);
    }

    private List<ConditionTemplate> generateAIUniversalTemplates() {
        try {
            ConditionTemplateContext context = ConditionTemplateContext.forUniversalTemplate();
            ConditionTemplateGenerationRequest request = new ConditionTemplateGenerationRequest(context);
            ConditionTemplateGenerationResponse response =
                    aiNativeProcessor.process(request, ConditionTemplateGenerationResponse.class).block();

            if (response != null && response.hasTemplates()) {
                return convertUniversalResponseToTemplates(response);
            }
            log.error("Universal condition template response is empty");
            return generateFallbackUniversalTemplates();
        } catch (Exception e) {
            log.error("AI universal template generation failed", e);
            return generateFallbackUniversalTemplates();
        }
    }

    private List<ConditionTemplate> convertUniversalResponseToTemplates(
            ConditionTemplateGenerationResponse response) {
        List<ConditionTemplate> templates = new ArrayList<>();
        Map<String, ConditionTemplateGenerationResponse.ConditionTemplateItem> batchResults =
                response.toConditionTemplateMap();

        for (Map.Entry<String, ConditionTemplateGenerationResponse.ConditionTemplateItem> entry
                : batchResults.entrySet()) {
            ConditionTemplateGenerationResponse.ConditionTemplateItem item = entry.getValue();
            if (item.getSpelTemplate() != null && !item.getSpelTemplate().trim().isEmpty()) {
                ConditionTemplate template = ConditionTemplate.builder()
                        .name(item.getName())
                        .description(item.getDescription())
                        .spelTemplate(item.getSpelTemplate())
                        .category(item.getCategory() != null ? item.getCategory() : "AI Generated")
                        .classification(parseClassification(item.getClassification()))
                        .sourceMethod("universal")
                        .isAutoGenerated(true)
                        .isUniversal(true)
                        .templateType("ai_generated")
                        .createdAt(LocalDateTime.now())
                        .build();
                templates.add(template);
            }
        }

        return templates;
    }

    private List<ConditionTemplate> processConditionBatch(List<ManagedResource> batch) {
        List<String> methodSignatures = batch.stream()
                .map(ManagedResource::getResourceIdentifier)
                .toList();

        List<Map<String, String>> resourceBatch = batch.stream()
                .map(r -> Map.of(
                        "identifier", r.getResourceIdentifier(),
                        "owner", r.getServiceOwner() != null ? r.getServiceOwner() : "Unknown"
                ))
                .collect(Collectors.toList());

        try {
            ConditionTemplateContext context = ConditionTemplateContext.forSpecificBatch(resourceBatch);
            ConditionTemplateGenerationRequest request = new ConditionTemplateGenerationRequest(context);
            request.withParameter("methodSignatures", methodSignatures);

            ConditionTemplateGenerationResponse response =
                    aiNativeProcessor.process(request, ConditionTemplateGenerationResponse.class).block();

            if (response != null && response.hasTemplates()) {
                return convertBatchResponseToTemplates(response, methodSignatures);
            }
            log.error("Specific condition template batch response is empty for {} methods", batch.size());
            return new ArrayList<>();

        } catch (Exception e) {
            log.error("Condition batch generation failed for {} methods", batch.size(), e);
            return new ArrayList<>();
        }
    }

    private List<ConditionTemplate> convertBatchResponseToTemplates(
            ConditionTemplateGenerationResponse response, List<String> methodSignatures) {
        List<ConditionTemplate> templates = new ArrayList<>();
        Map<String, ConditionTemplateGenerationResponse.ConditionTemplateItem> batchResults =
                response.toConditionTemplateMap();

        for (String methodSignature : methodSignatures) {
            ConditionTemplateGenerationResponse.ConditionTemplateItem item = batchResults.get(methodSignature);
            if (item != null && item.getSpelTemplate() != null && !item.getSpelTemplate().trim().isEmpty()) {
                ConditionTemplate template = ConditionTemplate.builder()
                        .name(item.getName())
                        .description(item.getDescription())
                        .spelTemplate(item.getSpelTemplate())
                        .category(item.getCategory() != null ? item.getCategory() : "AI Generated")
                        .classification(parseClassification(item.getClassification()))
                        .sourceMethod(methodSignature)
                        .isAutoGenerated(true)
                        .templateType("ai_generated")
                        .createdAt(LocalDateTime.now())
                        .build();
                templates.add(template);
            } else {
                log.error("No condition template generated for method: {}", methodSignature);
            }
        }

        return templates;
    }

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
        log.error("Unique name generation required timestamp fallback: {}", timestampName);
        return timestampName;
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
                .sourceMethod("fallback")
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
                .sourceMethod("fallback")
                .isAutoGenerated(true)
                .templateType("fallback")
                .createdAt(LocalDateTime.now())
                .build());

        return templates;
    }
}
