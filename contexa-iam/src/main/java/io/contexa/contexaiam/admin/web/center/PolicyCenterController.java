/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.admin.web.center;

import io.contexa.contexaiam.admin.web.center.dto.ConditionTemplateDto;
import io.contexa.contexaiam.admin.web.center.dto.BatchCreateRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyAvailablePermissionsResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyActionResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyApiResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyAiValidationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyBatchCreateResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyCleanupResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyErrorResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyFullValidationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyImpactResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyMatrixResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyMigrationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyPageResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyQuickCreateResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyResourceResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyRollbackRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyRoleResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicySimulationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicySpelPermissionResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicySystemStatsResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyValidationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionDiffResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionSnapshotResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionSummaryResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterPolicyRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicySummaryDto;
import io.contexa.contexaiam.admin.web.center.dto.PolicyResourceSearchRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicySimulationRequest;
import io.contexa.contexaiam.admin.web.center.dto.QuickPolicyRequest;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterAnalysisService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterPageService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterQueryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Collections;
import java.util.List;

/**
 * Policy Center - unified policy management controller.
 * Combines Resource Workbench, Policy Builder, Policy List, and Authorization Studio
 * into a single integrated interface.
 */
@Controller
@RequestMapping("/admin/policy-center")
@RequiredArgsConstructor
@Slf4j
public class PolicyCenterController {

    private final MessageSource messageSource;
    private final PolicyCenterPageService policyCenterPageService;
    private final PolicyCenterQueryService policyCenterQueryService;
    private final PolicyCenterCommandService policyCenterCommandService;
    private final PolicyCenterAnalysisService policyCenterAnalysisService;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    // ==================== Main Page ====================

    @GetMapping
    public String policyCenter(
            @RequestParam(required = false, defaultValue = "create") String tab,
            @ModelAttribute("criteria") PolicyResourceSearchRequest criteria,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable,
            @RequestParam(required = false) String policyKeyword,
            @RequestParam(required = false) String approvalStatus,
            @RequestParam(required = false) Boolean activeFilter,
            @RequestParam(required = false, defaultValue = "0") int policyPage,
            Model model) {

        try {
            policyCenterPageService.populatePolicyCenterModel(
                    model,
                    tab,
                    criteria,
                    pageable,
                    policyKeyword,
                    approvalStatus,
                    activeFilter,
                    policyPage);
        } catch (Exception e) {
            log.error("Failed to load policy center data", e);
            policyCenterPageService.populatePolicyCenterErrorModel(
                    model,
                    tab,
                    criteria,
                    msg("msg.policy.load.error"));
        }

        return "admin/policy-center";
    }

    // ==================== Resources Tab ====================

    @PostMapping("/refresh-resources")
    public String refreshResources(RedirectAttributes ra) {
        try {
            policyCenterCommandService.refreshResources();
            ra.addFlashAttribute("message", msg("msg.policy.resources.refreshed"));
        } catch (Exception e) {
            log.error("Failed to refresh resources", e);
            ra.addFlashAttribute("errorMessage", msg("msg.policy.refresh.error", e.getMessage()));
        }
        return "redirect:/admin/policy-center?tab=resources";
    }

    // ==================== Quick Mode API ====================

    @GetMapping("/api/roles")
    @ResponseBody
    public ResponseEntity<PolicyPageResponse<PolicyRoleResponse>> searchRoles(
            @RequestParam(required = false) String keyword,
            @PageableDefault(size = 20) Pageable pageable) {
        return ResponseEntity.ok(policyCenterQueryService.searchRoles(keyword, pageable));
    }

    @GetMapping("/api/available-permissions")
    @ResponseBody
    public ResponseEntity<PolicyAvailablePermissionsResponse> getAvailablePermissions(
            @RequestParam(required = false) List<Long> roleIds,
            @RequestParam(required = false) String keyword,
            @PageableDefault(size = 20) Pageable pageable) {
        return ResponseEntity.ok(policyCenterQueryService.getAvailablePermissions(roleIds, keyword, pageable));
    }

    @PostMapping("/api/quick-create")
    @ResponseBody
    public ResponseEntity<PolicyQuickCreateResponse> quickCreatePolicy(
            @RequestBody QuickPolicyRequest request) {
        PolicyQuickCreateResponse response = policyCenterCommandService.quickCreatePolicy(request);
        return Boolean.TRUE.equals(response.success())
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    // ==================== Resource Search API ====================

    @GetMapping("/api/resources")
    @ResponseBody
    public ResponseEntity<PolicyPageResponse<PolicyResourceResponse>> searchResourcesApi(
            @ModelAttribute PolicyResourceSearchRequest criteria,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        try {
            return ResponseEntity.ok(policyCenterQueryService.searchResources(criteria, pageable));
        } catch (IllegalArgumentException e) {
            log.warn("Invalid resource search criteria", e);
            return ResponseEntity.badRequest().body(new PolicyPageResponse<>(
                    Collections.emptyList(),
                    0,
                    0,
                    pageable.getPageNumber(),
                    pageable.getPageSize()
            ));
        }
    }

    // ==================== AI Wizard API ====================

    @GetMapping("/api/stats")
    @ResponseBody
    public ResponseEntity<PolicySystemStatsResponse> getSystemStats() {
        try {
            return ResponseEntity.ok(policyCenterQueryService.getSystemStats());
        } catch (Exception e) {
            log.error("Failed to load system stats", e);
            return ResponseEntity.ok(PolicySystemStatsResponse.basic(0L, 0L, 0L, 0L));
        }
    }

    @GetMapping("/api/policy-summaries")
    @ResponseBody
    public ResponseEntity<List<PolicySummaryDto>> getPolicySummaries() {
        try {
            return ResponseEntity.ok(policyCenterQueryService.getPolicySummaries());
        } catch (Exception e) {
            log.error("Failed to load policy summaries", e);
            return ResponseEntity.ok(Collections.emptyList());
        }
    }

    @GetMapping("/api/conditions")
    @ResponseBody
    public ResponseEntity<List<ConditionTemplateDto>> getConditions(
            @RequestParam(required = false) String keyword) {
        try {
            return ResponseEntity.ok(policyCenterQueryService.getConditions(keyword));
        } catch (Exception e) {
            log.error("Failed to load conditions", e);
            return ResponseEntity.ok(Collections.emptyList());
        }
    }

    // ==================== SpEL Permissions API ====================

    @GetMapping("/api/spel-permissions")
    @ResponseBody
    public ResponseEntity<List<PolicySpelPermissionResponse>> getSpelPermissions(
            @RequestParam(required = false) String keyword) {
        try {
            return ResponseEntity.ok(policyCenterQueryService.getSpelPermissions(keyword));
        } catch (Exception e) {
            log.error("Failed to load SpEL permissions", e);
            return ResponseEntity.ok(Collections.emptyList());
        }
    }

    // ==================== Manual Mode ====================

    @PostMapping("/create-policy")
    public String createPolicyFromCenter(@ModelAttribute PolicyCenterPolicyRequest request, RedirectAttributes ra) {
        PolicyActionResponse response = policyCenterCommandService.createPolicyFromCenter(request);
        if (Boolean.TRUE.equals(response.success())) {
            ra.addFlashAttribute("message", response.message());
        } else {
            ra.addFlashAttribute("errorMessage", response.message());
        }
        return "redirect:/admin/policy-center?tab=list";
    }

    // ==================== Policy Validation API ====================

    @GetMapping("/api/validation-report")
    @ResponseBody
    public ResponseEntity<PolicyFullValidationResponse> getValidationReport() {
        try {
            return ResponseEntity.ok(policyCenterAnalysisService.getValidationReport());
        } catch (Exception e) {
            log.error("Failed to generate validation report", e);
            return ResponseEntity.ok(new PolicyFullValidationResponse(
                    0, "UNKNOWN", List.of(), List.of()));
        }
    }

    @PostMapping("/api/validate")
    @ResponseBody
    public ResponseEntity<PolicyValidationResponse> validatePolicy(
            @RequestBody PolicyCenterPolicyRequest request) {
        try {
            return ResponseEntity.ok(policyCenterAnalysisService.validatePolicy(request));
        } catch (Exception e) {
            log.error("Failed to validate policy", e);
            return ResponseEntity.badRequest().body(new PolicyValidationResponse(
                    List.of(), List.of(), false, e.getMessage()));
        }
    }

    @PostMapping("/api/validate-quick")
    @ResponseBody
    public ResponseEntity<PolicyValidationResponse> validateQuickPolicy(
            @RequestBody QuickPolicyRequest request) {
        try {
            return ResponseEntity.ok(policyCenterAnalysisService.validateQuickPolicy(request));
        } catch (Exception e) {
            log.error("Failed to validate quick policy", e);
            return ResponseEntity.badRequest().body(new PolicyValidationResponse(
                    List.of(), List.of(), false, e.getMessage()));
        }
    }

    // ==================== AI Policy Validation API ====================

    @GetMapping("/api/{policyId}/ai-validation")
    @ResponseBody
    public ResponseEntity<PolicyAiValidationResponse> validateAIPolicy(@PathVariable Long policyId) {
        try {
            return ResponseEntity.ok(policyCenterAnalysisService.validateAIPolicy(policyId));
        } catch (Exception e) {
            log.error("Failed to validate AI policy {}", policyId, e);
            return ResponseEntity.ok(new PolicyAiValidationResponse(
                    List.of(), false, e.getMessage()));
        }
    }

    // ==================== Policy Simulation API ====================

    @PostMapping("/api/simulate")
    @ResponseBody
    public ResponseEntity<PolicySimulationResponse> simulate(@RequestBody PolicySimulationRequest request) {
        try {
            return ResponseEntity.ok(policyCenterAnalysisService.simulate(request));
        } catch (Exception e) {
            log.error("Failed to simulate policy", e);
            return ResponseEntity.ok(new PolicySimulationResponse(
                    List.of(),
                    new PolicySimulationResponse.SimulationSummary(0, 0, 0, 0)));
        }
    }

    // ==================== Reset Resource Policy Status API ====================

    @PostMapping("/api/reset-policy-status")
    @ResponseBody
    public ResponseEntity<PolicyActionResponse> resetPolicyStatus(@RequestBody List<Long> resourceIds) {
        PolicyActionResponse response = policyCenterCommandService.resetPolicyStatus(resourceIds);
        return Boolean.TRUE.equals(response.success())
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    // ==================== Batch Policy Creation API ====================

    @PostMapping("/api/batch-create")
    @ResponseBody
    public ResponseEntity<PolicyBatchCreateResponse> batchCreatePolicies(
            @RequestBody BatchCreateRequest request) {
        PolicyBatchCreateResponse response = policyCenterCommandService.batchCreatePolicies(request);
        return Boolean.TRUE.equals(response.success())
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    @PostMapping("/api/migrate-to-crud")
    @ResponseBody
    public ResponseEntity<PolicyMigrationResponse> migratePolicyExpressionsToCrud() {
        PolicyMigrationResponse response = policyCenterCommandService.migratePolicyExpressionsToCrud();
        return Boolean.TRUE.equals(response.success())
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    /**
     * Cleanup old auto-created per-resource permissions (URL_*, METHOD_*).
     * Should be run AFTER migrate-to-crud to remove orphaned permissions.
     */
    @PostMapping("/api/cleanup-old-permissions")
    @ResponseBody
    public ResponseEntity<PolicyCleanupResponse> cleanupOldAutoCreatedPermissions() {
        PolicyCleanupResponse response = policyCenterCommandService.cleanupOldAutoCreatedPermissions();
        return Boolean.TRUE.equals(response.success())
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    // ==================== Impact Analysis API ====================

    @PostMapping("/api/impact-analysis")
    @ResponseBody
    public ResponseEntity<PolicyApiResponse> analyzeImpact(
            @RequestBody PolicyCenterPolicyRequest request) {
        try {
            PolicyImpactResponse response = policyCenterAnalysisService.analyzeImpact(request);
            return ResponseEntity.<PolicyApiResponse>ok(response);
        } catch (Exception e) {
            log.error("Failed to analyze policy impact", e);
            return ResponseEntity.internalServerError()
                    .body(new PolicyErrorResponse(msg("msg.policy.impact.failed", e.getMessage())));
        }
    }

    // ==================== Policy Version API ====================

    @GetMapping("/api/{policyId}/versions")
    @ResponseBody
    public ResponseEntity<List<PolicyVersionSummaryResponse>> getVersions(@PathVariable Long policyId) {
        try {
            return ResponseEntity.ok(policyCenterQueryService.getVersions(policyId));
        } catch (Exception e) {
            log.error("Failed to load versions for policy {}", policyId, e);
            return ResponseEntity.ok(List.of());
        }
    }

    @GetMapping("/api/{policyId}/versions/{versionNumber}")
    @ResponseBody
    public ResponseEntity<PolicyVersionSnapshotResponse> getVersionSnapshot(
            @PathVariable Long policyId, @PathVariable int versionNumber) {
        try {
            return ResponseEntity.ok(policyCenterQueryService.getVersionSnapshot(policyId, versionNumber));
        } catch (Exception e) {
            log.error("Failed to load version snapshot for policy {}, version {}", policyId, versionNumber, e);
            return ResponseEntity.badRequest().body(new PolicyVersionSnapshotResponse(
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    e.getMessage()));
        }
    }

    @PostMapping("/api/{policyId}/rollback/{versionNumber}")
    @ResponseBody
    public ResponseEntity<PolicyActionResponse> rollbackPolicy(
            @PathVariable Long policyId,
            @PathVariable int versionNumber,
            @RequestBody(required = false) PolicyRollbackRequest body) {
        PolicyActionResponse response = policyCenterCommandService.rollbackPolicy(policyId, versionNumber, body);
        return Boolean.TRUE.equals(response.success())
                ? ResponseEntity.ok(response)
                : ResponseEntity.badRequest().body(response);
    }

    @GetMapping("/api/{policyId}/versions/compare")
    @ResponseBody
    public ResponseEntity<List<PolicyVersionDiffResponse>> compareVersions(
            @PathVariable Long policyId,
            @RequestParam int v1,
            @RequestParam int v2) {
        try {
            return ResponseEntity.ok(policyCenterQueryService.compareVersions(policyId, v1, v2));
        } catch (Exception e) {
            log.error("Failed to compare versions for policy {}", policyId, e);
            return ResponseEntity.ok(List.of());
        }
    }

    // ==================== Policy Matrix API ====================

    @GetMapping("/api/matrix")
    @ResponseBody
    public ResponseEntity<PolicyMatrixResponse> getMatrix(
            @RequestParam(required = false) String resourceFilter,
            @RequestParam(required = false) String roleFilter) {
        try {
            return ResponseEntity.ok(policyCenterAnalysisService.getMatrix(resourceFilter, roleFilter));
        } catch (Exception e) {
            log.error("Failed to generate policy matrix", e);
            return ResponseEntity.ok(new PolicyMatrixResponse(
                    List.of(), List.of(), List.of(), List.of(), 0, 1, 0));
        }
    }
}
