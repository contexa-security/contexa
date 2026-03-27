package io.contexa.contexaiam.resource.controller;

import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import io.contexa.contexaiam.resource.service.CompatibilityResult;
import io.contexa.contexaiam.resource.service.AutoConditionTemplateService;
import io.contexa.contexacommon.entity.ManagedResource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

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
    public ResponseEntity<Map<String, Object>> getClassifiedConditions() {
        List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();
        
        Map<ConditionTemplate.ConditionClassification, List<ConditionTemplate>> classifiedConditions = 
            allConditions.stream()
                .collect(Collectors.groupingBy(
                    condition -> condition.getClassification() != null ? 
                        condition.getClassification() : ConditionTemplate.ConditionClassification.UNIVERSAL));

        Map<String, Object> response = new HashMap<>();
        response.put("total", allConditions.size());
        response.put("byClassification", classifiedConditions);
        response.put("statistics", calculateStatistics(allConditions));

                return ResponseEntity.ok(response);
    }

    @GetMapping("/compatible/{resourceId}")
    public ResponseEntity<Map<String, Object>> getCompatibleConditions(@PathVariable Long resourceId) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
            .orElseThrow(() -> new IllegalArgumentException("Resource not found: " + resourceId));

        List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();
        Map<Long, CompatibilityResult> compatibilityResults = 
            compatibilityService.checkBatchCompatibility(allConditions, resource);

        Map<ConditionTemplate.ConditionClassification, List<ConditionInfo>> compatibleByClass = 
            new EnumMap<>(ConditionTemplate.ConditionClassification.class);

        for (ConditionTemplate condition : allConditions) {
            CompatibilityResult result = compatibilityResults.get(condition.getId());
            if (result != null && result.isCompatible()) {
                ConditionInfo condInfo = new ConditionInfo(condition, result);
                compatibleByClass.computeIfAbsent(condition.getClassification(), 
                    k -> new ArrayList<>()).add(condInfo);
            }
        }

        Map<String, Object> response = new HashMap<>();
        response.put("resourceId", resourceId);
        response.put("resourceIdentifier", resource.getResourceIdentifier());
        response.put("compatibleConditions", compatibleByClass);
        response.put("totalCompatible", compatibilityResults.values().stream()
            .mapToInt(r -> r.isCompatible() ? 1 : 0).sum());
        response.put("totalChecked", allConditions.size());

        return ResponseEntity.ok(response);
    }

    @PutMapping("/{conditionId}/classification")
    public ResponseEntity<Map<String, Object>> updateConditionClassification(
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

        Map<String, Object> response = new HashMap<>();
        response.put("conditionId", conditionId);
        response.put("oldClassification", oldClassification);
        response.put("newClassification", condition.getClassification());
        response.put("updated", true);

        return ResponseEntity.ok(response);
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
    public ResponseEntity<Map<String, Object>> regenerateFixedTemplates() {
                
        try {
            
            long resourceCount = managedResourceRepository.count();
            if (resourceCount == 0) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("success", false);
                errorResponse.put("error", "No ManagedResource data found");
                errorResponse.put("message", "Please run resource scan first");
                errorResponse.put("resourceCount", 0);
                return ResponseEntity.badRequest().body(errorResponse);
            }

            conditionTemplateRepository.deleteByIsAutoGenerated(true);

            List<ConditionTemplate> generatedTemplates = autoConditionTemplateService.generateConditionTemplates();
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("deletedOldTemplates", true);
            response.put("generatedCount", generatedTemplates.size());
            response.put("message", "Cleaned up invalid conditions and regenerated correct condition templates");
            response.put("templates", generatedTemplates.stream()
                .map(template -> Map.of(
                    "id", template.getId(),
                    "name", template.getName(),
                    "description", template.getDescription(),
                    "spelTemplate", template.getSpelTemplate(),
                    "classification", template.getClassification()
                ))
                .collect(Collectors.toList()));
            
                        return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to regenerate condition templates", e);

            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", e.getMessage());
            errorResponse.put("message", "An error occurred while regenerating condition templates");
            
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    @PostMapping("/generate-managed-resource-based")
    public ResponseEntity<Map<String, Object>> generateManagedResourceBasedTemplates() {
                
        try {
            List<ConditionTemplate> generatedTemplates = autoConditionTemplateService.generateConditionTemplates();
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("generatedCount", generatedTemplates.size());
            response.put("message", "ManagedResource-based condition templates have been successfully generated");
            response.put("templates", generatedTemplates.stream()
                .map(template -> Map.of(
                    "id", template.getId(),
                    "name", template.getName(),
                    "description", template.getDescription(),
                    "classification", template.getClassification(),
                    "sourceMethod", template.getSourceMethod()
                ))
                .collect(Collectors.toList()));
            
                        return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to generate ManagedResource-based condition templates", e);

            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", e.getMessage());
            errorResponse.put("message", "An error occurred while generating condition templates");
            
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    @PostMapping("/generate-permission-based")
    public ResponseEntity<Map<String, Object>> generatePermissionBasedTemplates() {
                
        try {
            List<ConditionTemplate> generatedTemplates = autoConditionTemplateService.generateConditionTemplates();
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("generatedCount", generatedTemplates.size());
            response.put("message", "Permission-based condition templates have been successfully generated");
            response.put("templates", generatedTemplates.stream()
                .map(template -> Map.of(
                    "id", template.getId(),
                    "name", template.getName(),
                    "description", template.getDescription(),
                    "classification", template.getClassification(),
                    "sourceMethod", template.getSourceMethod()
                ))
                .collect(Collectors.toList()));
            
                        return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to generate Permission-based condition templates", e);

            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", e.getMessage());
            errorResponse.put("message", "An error occurred while generating condition templates");
            
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    private Map<String, Object> calculateStatistics(List<ConditionTemplate> conditions) {
        Map<String, Object> stats = new HashMap<>();
        
        long autoGenerated = conditions.stream().mapToLong(c -> 
            Boolean.TRUE.equals(c.getIsAutoGenerated()) ? 1 : 0).sum();
        long manual = conditions.size() - autoGenerated;
        
        stats.put("autoGenerated", autoGenerated);
        stats.put("manual", manual);
        stats.put("avgComplexityScore", conditions.stream()
            .mapToInt(c -> c.getComplexityScore() != null ? c.getComplexityScore() : 1)
            .average().orElse(0.0));
        
        return stats;
    }

    public static class ConditionInfo {
        public final Long id;
        public final String name;
        public final String description;
        public final ConditionTemplate.ConditionClassification classification;
        public final Integer complexityScore;
        public final Boolean approvalRequired;
        public final String compatibilityReason;

        public ConditionInfo(ConditionTemplate condition, CompatibilityResult result) {
            this.id = condition.getId();
            this.name = condition.getName();
            this.description = condition.getDescription();
            this.classification = condition.getClassification();
            this.complexityScore = condition.getComplexityScore();
            this.approvalRequired = condition.getApprovalRequired();
            this.compatibilityReason = result.getReason();
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