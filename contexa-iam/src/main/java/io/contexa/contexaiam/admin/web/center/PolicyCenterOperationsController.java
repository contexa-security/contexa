/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaiam.admin.web.center;

import io.contexa.contexaiam.admin.web.center.dto.BatchCreateRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyActionResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyApiResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyBatchCreateResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyCleanupResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyErrorResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyImpactResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyMatrixResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyMigrationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicySimulationResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionDiffResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionSnapshotResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyVersionSummaryResponse;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterDtos.PolicyRollbackRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterPolicyRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicySimulationRequest;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterAnalysisService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterCommandService;
import io.contexa.contexaiam.admin.web.center.service.PolicyCenterQueryService;
import io.contexa.contexaiam.common.ConsoleFault;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.List;

@Controller
@RequestMapping("/contexa/admin/policy-center")
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PolicyCenterOperationsController {

    private final MessageSource messageSource;
    private final PolicyCenterQueryService policyCenterQueryService;
    private final PolicyCenterCommandService policyCenterCommandService;
    private final PolicyCenterAnalysisService policyCenterAnalysisService;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    // ==================== Policy Simulation API ====================

    // D75: a read or an analysis that fails reaches the global exception handler, which logs it and answers with its
    // error status, instead of 200 with empty results.
    @PostMapping("/api/simulate")
    @ResponseBody
    public ResponseEntity<PolicySimulationResponse> simulate(@RequestBody PolicySimulationRequest request) {
        return ResponseEntity.ok(policyCenterAnalysisService.simulate(request));
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
            ConsoleFault.report(e, log, "analyze the impact of a policy");
            return ResponseEntity.internalServerError()
                    .body(new PolicyErrorResponse(msg("msg.policy.impact.failed", e.getMessage())));
        }
    }

    // ==================== Policy Version API ====================

    @GetMapping("/api/{policyId}/versions")
    @ResponseBody
    public ResponseEntity<List<PolicyVersionSummaryResponse>> getVersions(@PathVariable Long policyId) {
        return ResponseEntity.ok(policyCenterQueryService.getVersions(policyId));
    }

    @GetMapping("/api/{policyId}/versions/{versionNumber}")
    @ResponseBody
    public ResponseEntity<PolicyVersionSnapshotResponse> getVersionSnapshot(
            @PathVariable Long policyId, @PathVariable int versionNumber) {
        try {
            return ResponseEntity.ok(policyCenterQueryService.getVersionSnapshot(policyId, versionNumber));
        } catch (Exception e) {
            ConsoleFault.report(e, log, "load version " + versionNumber + " of policy " + policyId);
            return ResponseEntity.badRequest().body(new PolicyVersionSnapshotResponse(
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    ConsoleFault.textOf(e)));
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
        return ResponseEntity.ok(policyCenterQueryService.compareVersions(policyId, v1, v2));
    }

    // ==================== Policy Matrix API ====================

    @GetMapping("/api/matrix")
    @ResponseBody
    public ResponseEntity<PolicyMatrixResponse> getMatrix(
            @RequestParam(required = false) String resourceFilter,
            @RequestParam(required = false) String roleFilter) {
        return ResponseEntity.ok(policyCenterAnalysisService.getMatrix(resourceFilter, roleFilter));
    }
}
