package io.contexa.contexaiam.resource.controller;

import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.dto.ConditionClassificationDtos.ClassificationUpdateResponse;
import io.contexa.contexaiam.resource.dto.ConditionClassificationDtos.ClassifiedConditionsResponse;
import io.contexa.contexaiam.resource.dto.ConditionClassificationDtos.CompatibleConditionsResponse;
import io.contexa.contexaiam.resource.dto.ConditionClassificationDtos.ConditionTemplateGenerationErrorResponse;
import io.contexa.contexaiam.resource.dto.ConditionClassificationDtos.ConditionTemplateGenerationResponse;
import io.contexa.contexaiam.resource.dto.ConditionClassificationDtos.GeneratedTemplatesResponse;
import io.contexa.contexaiam.resource.dto.ConditionClassificationDtos.NoManagedResourceResponse;
import io.contexa.contexaiam.resource.dto.ConditionClassificationDtos.RegeneratedTemplatesResponse;
import io.contexa.contexaiam.resource.service.AutoConditionTemplateService;
import io.contexa.contexaiam.resource.service.CompatibilityResult;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import io.contexa.contexacommon.entity.ManagedResource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin/api/conditions")
@RequiredArgsConstructor
@Slf4j
public class ConditionClassificationController {

    private final ConditionTemplateRepository conditionTemplateRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final ConditionCompatibilityService compatibilityService;
    private final AutoConditionTemplateService autoConditionTemplateService;

    @GetMapping("/classified")
    public ResponseEntity<ClassifiedConditionsResponse> getClassifiedConditions() {
        List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();
        return ResponseEntity.ok(ClassifiedConditionsResponse.from(allConditions));
    }

    @GetMapping("/compatible/{resourceId}")
    public ResponseEntity<CompatibleConditionsResponse> getCompatibleConditions(@PathVariable Long resourceId) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
            .orElseThrow(() -> new IllegalArgumentException("Resource not found: " + resourceId));

        List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();

        return ResponseEntity.ok(CompatibleConditionsResponse.from(
                resourceId,
                resource.getResourceIdentifier(),
                allConditions,
                compatibilityService.checkBatchCompatibility(allConditions, resource)));
    }

    @PutMapping("/{conditionId}/classification")
    public ResponseEntity<ClassificationUpdateResponse> updateConditionClassification(
            @PathVariable Long conditionId,
            @RequestBody ClassificationUpdateRequest request) {

        ConditionTemplate condition = conditionTemplateRepository.findById(conditionId)
            .orElseThrow(() -> new IllegalArgumentException("Condition not found: " + conditionId));

        ConditionTemplate.ConditionClassification oldClassification = condition.getClassification();

        condition.setClassification(request.classification);
        condition.setApprovalRequired(request.approvalRequired);
        condition.setContextDependent(request.contextDependent);
        
        if (request.complexityScore != null) {
            condition.setComplexityScore(request.complexityScore);
        }

        conditionTemplateRepository.save(condition);

        return ResponseEntity.ok(new ClassificationUpdateResponse(
                conditionId,
                oldClassification,
                condition.getClassification(),
                true));
    }

    @PostMapping("/check-compatibility")
    public ResponseEntity<CompatibilityResult> checkCompatibility(@RequestBody CompatibilityCheckRequest request) {
        ConditionTemplate condition = conditionTemplateRepository.findById(request.conditionId)
            .orElseThrow(() -> new IllegalArgumentException("Condition not found: " + request.conditionId));

        ManagedResource resource = managedResourceRepository.findById(request.resourceId)
            .orElseThrow(() -> new IllegalArgumentException("Resource not found: " + request.resourceId));

        CompatibilityResult result = compatibilityService.checkCompatibility(condition, resource);

        return ResponseEntity.ok(result);
    }

    @PostMapping("/regenerate-fixed-templates")
    public ResponseEntity<ConditionTemplateGenerationResponse> regenerateFixedTemplates() {
                
        try {
            
            long resourceCount = managedResourceRepository.count();
            if (resourceCount == 0) {
                return ResponseEntity.<ConditionTemplateGenerationResponse>badRequest()
                        .body(new NoManagedResourceResponse(
                                false,
                                "No ManagedResource data found",
                                "Please run resource scan first",
                                0));
            }

            conditionTemplateRepository.deleteByIsAutoGenerated(true);

            List<ConditionTemplate> generatedTemplates = autoConditionTemplateService.generateConditionTemplates();
            return ResponseEntity.<ConditionTemplateGenerationResponse>ok(
                    RegeneratedTemplatesResponse.success(generatedTemplates));
            
        } catch (Exception e) {
            log.error("Failed to regenerate condition templates", e);

            return ResponseEntity.internalServerError()
                    .body(ConditionTemplateGenerationErrorResponse.from(
                            e,
                            "An error occurred while regenerating condition templates"));
        }
    }

    @PostMapping("/generate-managed-resource-based")
    public ResponseEntity<ConditionTemplateGenerationResponse> generateManagedResourceBasedTemplates() {
                
        try {
            List<ConditionTemplate> generatedTemplates = autoConditionTemplateService.generateConditionTemplates();
            return ResponseEntity.<ConditionTemplateGenerationResponse>ok(
                    GeneratedTemplatesResponse.success(
                            generatedTemplates,
                            "ManagedResource-based condition templates have been successfully generated"));
            
        } catch (Exception e) {
            log.error("Failed to generate ManagedResource-based condition templates", e);

            return ResponseEntity.internalServerError()
                    .body(ConditionTemplateGenerationErrorResponse.from(
                            e,
                            "An error occurred while generating condition templates"));
        }
    }

    @PostMapping("/generate-permission-based")
    public ResponseEntity<ConditionTemplateGenerationResponse> generatePermissionBasedTemplates() {
                
        try {
            List<ConditionTemplate> generatedTemplates = autoConditionTemplateService.generateConditionTemplates();
            return ResponseEntity.<ConditionTemplateGenerationResponse>ok(
                    GeneratedTemplatesResponse.success(
                            generatedTemplates,
                            "Permission-based condition templates have been successfully generated"));
            
        } catch (Exception e) {
            log.error("Failed to generate Permission-based condition templates", e);

            return ResponseEntity.internalServerError()
                    .body(ConditionTemplateGenerationErrorResponse.from(
                            e,
                            "An error occurred while generating condition templates"));
        }
    }

    public static class ClassificationUpdateRequest {
        public ConditionTemplate.ConditionClassification classification;
        public Boolean approvalRequired;
        public Boolean contextDependent;
        public Integer complexityScore;
    }

    public static class CompatibilityCheckRequest {
        public Long conditionId;
        public Long resourceId;
    }
}
