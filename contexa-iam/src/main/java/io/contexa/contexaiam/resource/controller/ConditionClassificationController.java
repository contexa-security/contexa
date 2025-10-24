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

/**
 * 2단계: 조건 분류 및 호환성 검사를 위한 REST API
 */
@RestController
@RequestMapping("/api/conditions")
@RequiredArgsConstructor
@Slf4j
public class ConditionClassificationController {

    private final ConditionTemplateRepository conditionTemplateRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final ConditionCompatibilityService compatibilityService;
    private final AutoConditionTemplateService autoConditionTemplateService;

    /**
     * 분류된 조건 목록을 반환합니다.
     */
    @GetMapping("/classified")
    public ResponseEntity<Map<String, Object>> getClassifiedConditions() {
        List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();
        
        Map<ConditionTemplate.ConditionClassification, List<ConditionTemplate>> classifiedConditions = 
            allConditions.stream()
                .collect(Collectors.groupingBy(
                    condition -> condition.getClassification() != null ? 
                        condition.getClassification() : ConditionTemplate.ConditionClassification.UNIVERSAL));

        Map<ConditionTemplate.RiskLevel, List<ConditionTemplate>> riskGrouped = 
            compatibilityService.groupByRiskLevel(allConditions);

        Map<String, Object> response = new HashMap<>();
        response.put("total", allConditions.size());
        response.put("byClassification", classifiedConditions);
        response.put("byRiskLevel", riskGrouped);
        response.put("statistics", calculateStatistics(allConditions));

        log.info("분류된 조건 목록 요청: 총 {} 개", allConditions.size());
        return ResponseEntity.ok(response);
    }

    /**
     * 특정 리소스와 호환되는 조건들을 반환합니다.
     */
    @GetMapping("/compatible/{resourceId}")
    public ResponseEntity<Map<String, Object>> getCompatibleConditions(@PathVariable Long resourceId) {
        ManagedResource resource = managedResourceRepository.findById(resourceId)
            .orElseThrow(() -> new IllegalArgumentException("Resource not found: " + resourceId));

        List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();
        Map<Long, CompatibilityResult> compatibilityResults = 
            compatibilityService.checkBatchCompatibility(allConditions, resource);

        // 호환 가능한 조건들을 분류별로 그룹화
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

        log.info("리소스 {} 호환 조건 검사: {} 개 중 {} 개 호환", 
            resourceId, allConditions.size(), 
            compatibilityResults.values().stream().mapToInt(r -> r.isCompatible() ? 1 : 0).sum());

        return ResponseEntity.ok(response);
    }

    /**
     * 조건의 분류를 수동으로 업데이트합니다.
     */
    @PutMapping("/{conditionId}/classification")
    public ResponseEntity<Map<String, Object>> updateConditionClassification(
            @PathVariable Long conditionId,
            @RequestBody ClassificationUpdateRequest request) {

        ConditionTemplate condition = conditionTemplateRepository.findById(conditionId)
            .orElseThrow(() -> new IllegalArgumentException("Condition not found: " + conditionId));

        ConditionTemplate.ConditionClassification oldClassification = condition.getClassification();
        
        // 분류 업데이트
        condition.setClassification(request.classification);
        condition.setRiskLevel(request.riskLevel);
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

        log.info("조건 {} 분류 업데이트: {} → {}", 
            conditionId, oldClassification, condition.getClassification());

        return ResponseEntity.ok(response);
    }

    /**
     * 조건 호환성을 실시간으로 검사합니다.
     */
    @PostMapping("/check-compatibility")
    public ResponseEntity<CompatibilityResult> checkCompatibility(@RequestBody CompatibilityCheckRequest request) {
        ConditionTemplate condition = conditionTemplateRepository.findById(request.conditionId)
            .orElseThrow(() -> new IllegalArgumentException("Condition not found: " + request.conditionId));

        ManagedResource resource = managedResourceRepository.findById(request.resourceId)
            .orElseThrow(() -> new IllegalArgumentException("Resource not found: " + request.resourceId));

        CompatibilityResult result = compatibilityService.checkCompatibility(condition, resource);
        
        log.debug("호환성 검사: 조건 {} vs 리소스 {} = {}", 
            request.conditionId, request.resourceId, result.isCompatible());

        return ResponseEntity.ok(result);
    }

    /**
     * 수정: 잘못된 조건 템플릿들을 정리하고 올바른 조건을 재생성
     */
    @PostMapping("/regenerate-fixed-templates")
    public ResponseEntity<Map<String, Object>> regenerateFixedTemplates() {
        log.info("잘못된 조건 템플릿 정리 및 재생성 요청");
        
        try {
            // 1. 먼저 ManagedResource 데이터가 있는지 확인
            long resourceCount = managedResourceRepository.count();
            if (resourceCount == 0) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("success", false);
                errorResponse.put("error", "ManagedResource 데이터가 없습니다");
                errorResponse.put("message", "먼저 리소스 스캔을 실행해주세요");
                errorResponse.put("resourceCount", 0);
                return ResponseEntity.badRequest().body(errorResponse);
            }
            
            log.info("현재 ManagedResource 수: {} 개", resourceCount);
            
            // 2. 기존 자동 생성 조건들 삭제 (isAutoGenerated = true)
            conditionTemplateRepository.deleteByIsAutoGenerated(true);
            log.info("기존 자동 생성 조건 템플릿 삭제 완료");
            
            // 3. ManagedResource 기반 새 조건 생성
            List<ConditionTemplate> generatedTemplates = autoConditionTemplateService.generateConditionTemplates();
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("deletedOldTemplates", true);
            response.put("generatedCount", generatedTemplates.size());
            response.put("message", "잘못된 조건들을 정리하고 올바른 조건 템플릿을 재생성했습니다");
            response.put("templates", generatedTemplates.stream()
                .map(template -> Map.of(
                    "id", template.getId(),
                    "name", template.getName(),
                    "description", template.getDescription(),
                    "spelTemplate", template.getSpelTemplate(),
                    "classification", template.getClassification()
                ))
                .collect(Collectors.toList()));
            
            log.info("조건 템플릿 재생성 완료: {} 개", generatedTemplates.size());
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("조건 템플릿 재생성 실패", e);
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", e.getMessage());
            errorResponse.put("message", "조건 템플릿 재생성 중 오류가 발생했습니다");
            
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    /**
     * 개선: ManagedResource 기반 조건 템플릿 생성
     * ManagedResource의 friendlyName을 기반으로 조건들을 생성합니다.
     */
    @PostMapping("/generate-managed-resource-based")
    public ResponseEntity<Map<String, Object>> generateManagedResourceBasedTemplates() {
        log.info("ManagedResource 기반 조건 템플릿 생성 요청");
        
        try {
            List<ConditionTemplate> generatedTemplates = autoConditionTemplateService.generateConditionTemplates();
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("generatedCount", generatedTemplates.size());
            response.put("message", "ManagedResource 기반 조건 템플릿이 성공적으로 생성되었습니다");
            response.put("templates", generatedTemplates.stream()
                .map(template -> Map.of(
                    "id", template.getId(),
                    "name", template.getName(),
                    "description", template.getDescription(),
                    "classification", template.getClassification(),
                    "sourceMethod", template.getSourceMethod()
                ))
                .collect(Collectors.toList()));
            
            log.info("ManagedResource 기반 조건 템플릿 생성 완료: {} 개", generatedTemplates.size());
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("ManagedResource 기반 조건 템플릿 생성 실패", e);
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", e.getMessage());
            errorResponse.put("message", "조건 템플릿 생성 중 오류가 발생했습니다");
            
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    /**
     * 개선: Permission 기반 조건 템플릿 생성
     * 실제 권한명과 매칭되는 조건들을 생성합니다.
     */
    @PostMapping("/generate-permission-based")
    public ResponseEntity<Map<String, Object>> generatePermissionBasedTemplates() {
        log.info("Permission 기반 조건 템플릿 생성 요청");
        
        try {
            List<ConditionTemplate> generatedTemplates = autoConditionTemplateService.generateConditionTemplates();
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("generatedCount", generatedTemplates.size());
            response.put("message", "Permission 기반 조건 템플릿이 성공적으로 생성되었습니다");
            response.put("templates", generatedTemplates.stream()
                .map(template -> Map.of(
                    "id", template.getId(),
                    "name", template.getName(),
                    "description", template.getDescription(),
                    "classification", template.getClassification(),
                    "sourceMethod", template.getSourceMethod()
                ))
                .collect(Collectors.toList()));
            
            log.info("Permission 기반 조건 템플릿 생성 완료: {} 개", generatedTemplates.size());
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Permission 기반 조건 템플릿 생성 실패", e);
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", e.getMessage());
            errorResponse.put("message", "조건 템플릿 생성 중 오류가 발생했습니다");
            
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    /**
     * 분류별 조건 통계를 계산합니다.
     */
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

    /**
     * 조건 정보를 담는 내부 DTO
     */
    public static class ConditionInfo {
        public final Long id;
        public final String name;
        public final String description;
        public final ConditionTemplate.ConditionClassification classification;
        public final ConditionTemplate.RiskLevel riskLevel;
        public final Integer complexityScore;
        public final Boolean approvalRequired;
        public final String compatibilityReason;

        public ConditionInfo(ConditionTemplate condition, CompatibilityResult result) {
            this.id = condition.getId();
            this.name = condition.getName();
            this.description = condition.getDescription();
            this.classification = condition.getClassification();
            this.riskLevel = condition.getRiskLevel();
            this.complexityScore = condition.getComplexityScore();
            this.approvalRequired = condition.getApprovalRequired();
            this.compatibilityReason = result.getReason();
        }
    }

    /**
     * 분류 업데이트 요청 DTO
     */
    public static class ClassificationUpdateRequest {
        public ConditionTemplate.ConditionClassification classification;
        public ConditionTemplate.RiskLevel riskLevel;
        public Boolean approvalRequired;
        public Boolean contextDependent;
        public Integer complexityScore;
    }

    /**
     * 호환성 검사 요청 DTO
     */
    public static class CompatibilityCheckRequest {
        public Long conditionId;
        public Long resourceId;
    }
} 