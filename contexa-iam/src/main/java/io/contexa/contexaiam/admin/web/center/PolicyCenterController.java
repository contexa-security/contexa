package io.contexa.contexaiam.admin.web.center;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.dto.ConditionTemplateDto;
import io.contexa.contexaiam.admin.web.center.dto.PolicySummaryDto;
import io.contexa.contexaiam.admin.web.center.dto.QuickPolicyRequest;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.ResourceSearchCriteria;
import io.contexa.contexaiam.domain.dto.RoleDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.dto.TargetDto;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.domain.entity.SecuritySpel;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.repository.SecuritySpelRepository;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyMatrixService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.dto.AIPolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyMatrixReport;
import io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyImpactReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationRequest;
import io.contexa.contexaiam.security.xacml.pap.service.BusinessPolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyVersionService;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.*;
import java.util.stream.Collectors;

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

    private final ResourceRegistryService resourceRegistryService;
    private final PolicyService policyService;
    private final PolicyRepository policyRepository;
    private final RoleService roleService;
    private final PermissionCatalogService permissionCatalogService;
    private final BusinessPolicyService businessPolicyService;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final SecuritySpelRepository securitySpelRepository;
    private final MessageSource messageSource;
    private final PolicyValidationService policyValidationService;
    private final PermissionRepository permissionRepository;
    private final PolicyVersionService policyVersionService;
    private final PolicyMatrixService policyMatrixService;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    // ==================== Main Page ====================

    @GetMapping
    public String policyCenter(
            @RequestParam(required = false, defaultValue = "create") String tab,
            @ModelAttribute("criteria") ResourceSearchCriteria criteria,
            @PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable,
            @RequestParam(required = false) String policyKeyword,
            @RequestParam(required = false, defaultValue = "0") int policyPage,
            Model model) {

        model.addAttribute("activePage", "policy-center");
        model.addAttribute("activeTab", tab);

        try {
            // Resources tab data
            Page<ManagedResource> resourcePage = resourceRegistryService.findResources(criteria, pageable);
            Set<String> serviceOwners = resourceRegistryService.getAllServiceOwners();
            model.addAttribute("resourcePage", resourcePage);
            model.addAttribute("serviceOwners", serviceOwners);
            model.addAttribute("criteria", criteria);

            // Policy creation tab - manual mode: empty PolicyDto
            PolicyDto emptyPolicy = new PolicyDto();
            emptyPolicy.getTargets().add(new TargetDto());
            emptyPolicy.getRules().add(new RuleDto());
            model.addAttribute("policy", emptyPolicy);

            // Policy list tab data (server-side pagination)
            Pageable policyPageable = org.springframework.data.domain.PageRequest.of(
                    policyPage, 10, Sort.by(Sort.Direction.DESC, "id"));
            Page<Policy> policyPageResult = policyService.searchPolicies(policyKeyword, policyPageable);
            model.addAttribute("policyPage", policyPageResult);
            model.addAttribute("policyKeyword", policyKeyword);

        } catch (Exception e) {
            log.error("Failed to load policy center data", e);
            model.addAttribute("resourcePage", Page.empty());
            model.addAttribute("serviceOwners", Collections.emptySet());
            model.addAttribute("policy", new PolicyDto());
            model.addAttribute("policyPage", Page.empty());
            model.addAttribute("errorMessage", msg("msg.policy.load.error"));
        }

        return "admin/policy-center";
    }

    // ==================== Resources Tab ====================

    @PostMapping("/refresh-resources")
    public String refreshResources(RedirectAttributes ra) {
        try {
            resourceRegistryService.refreshAndSynchronizeResources();
            synchronizeResourcePolicyStatus();
            ra.addFlashAttribute("message", msg("msg.policy.resources.refreshed"));
        } catch (Exception e) {
            log.error("Failed to refresh resources", e);
            ra.addFlashAttribute("errorMessage", msg("msg.policy.refresh.error", e.getMessage()));
        }
        return "redirect:/admin/policy-center?tab=resources";
    }

    private void synchronizeResourcePolicyStatus() {
        try {
            Set<String> allPolicyTargets = policyService.getAllPolicies().stream()
                    .flatMap(p -> p.getTargets().stream())
                    .map(t -> t.getTargetType() + ":" + t.getTargetIdentifier())
                    .collect(java.util.stream.Collectors.toSet());

            managedResourceRepository.findByStatusInWithPermission(
                    List.of(ManagedResource.Status.POLICY_CONNECTED)
            ).forEach(resource -> {
                String key = resource.getResourceType().name() + ":" + resource.getResourceIdentifier();
                if (!allPolicyTargets.contains(key)) {
                    resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);
                    managedResourceRepository.save(resource);
                }
            });
        } catch (Exception e) {
            log.error("Failed to synchronize resource policy status", e);
        }
    }

    // ==================== Quick Mode API ====================

    @GetMapping("/api/roles")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> searchRoles(
            @RequestParam(required = false) String keyword,
            @PageableDefault(size = 20) Pageable pageable) {
        Page<Role> roles = roleService.searchRoles(keyword, pageable);
        Page<RoleDto> dtoPage = roles.map(r -> RoleDto.builder()
                .id(r.getId())
                .roleName(r.getRoleName())
                .roleDesc(r.getRoleDesc())
                .build());
        return ResponseEntity.ok(toPageResponse(dtoPage));
    }

    @GetMapping("/api/available-permissions")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getAvailablePermissions(
            @RequestParam(required = false) List<Long> roleIds,
            @RequestParam(required = false) String keyword,
            @PageableDefault(size = 20) Pageable pageable) {
        Set<Long> allMappedPermIds = new HashSet<>();
        Map<String, List<Long>> rolePermissionMap = new HashMap<>();
        if (roleIds != null) {
            for (Long roleId : roleIds) {
                if (roleId == null || roleId <= 0) continue;
                try {
                    Role role = roleService.getRole(roleId);
                    List<Long> permIds = new ArrayList<>();
                    role.getRolePermissions().forEach(rp -> {
                        Long pid = rp.getPermission().getId();
                        allMappedPermIds.add(pid);
                        permIds.add(pid);
                    });
                    rolePermissionMap.put(String.valueOf(roleId), permIds);
                } catch (Exception e) {
                    log.error("Failed to load role {}", roleId, e);
                }
            }
        }
        Page<PermissionDto> allPermissions = permissionCatalogService
                .searchAvailablePermissions(keyword, Collections.emptySet(), pageable);
        Map<String, Object> response = toPageResponse(allPermissions);
        response.put("alreadyMappedIds", allMappedPermIds);
        response.put("rolePermissionMap", rolePermissionMap);
        return ResponseEntity.ok(response);
    }

    private <T> Map<String, Object> toPageResponse(Page<T> page) {
        Map<String, Object> response = new HashMap<>();
        response.put("content", page.getContent());
        response.put("totalElements", page.getTotalElements());
        response.put("totalPages", page.getTotalPages());
        response.put("number", page.getNumber());
        response.put("size", page.getSize());
        return response;
    }

    @PostMapping("/api/quick-create")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> quickCreatePolicy(
            @RequestBody QuickPolicyRequest request) {
        try {
            BusinessPolicyDto dto = new BusinessPolicyDto();
            dto.setPolicyName(request.getPolicyName());
            dto.setDescription(request.getDescription());
            dto.setEffect(request.getEffect());
            dto.setRoleIds(request.getRoleIds());
            dto.setPermissionIds(request.getPermissionIds());
            dto.setConditions(Collections.emptyMap());
            dto.setSource(Policy.PolicySource.MANUAL);
            dto.setSpelId(request.getSpelId());

            // Manual target support
            if ("MANUAL".equals(request.getSourceType())) {
                dto.setSourceType("MANUAL");
                dto.setManualTargetType(request.getManualTargetType());
                dto.setManualTargetIdentifier(request.getManualTargetIdentifier());
                dto.setManualHttpMethod(request.getManualHttpMethod());
                dto.setManualTargetOrder(request.getManualTargetOrder());
            }

            List<String> duplicateAutoRoles = new ArrayList<>();
            if (request.getRoleIds() != null) {
                for (Long roleId : request.getRoleIds()) {
                    try {
                        Role role = roleService.getRole(roleId);
                        String autoPolicyName = "AUTO_POLICY_FOR_" + role.getRoleName();
                        if (policyRepository.findByName(autoPolicyName).isPresent()) {
                            duplicateAutoRoles.add(role.getRoleName());
                        }
                    } catch (Exception ignored) {
                    }
                }
            }

            Policy saved = businessPolicyService.createPolicyFromBusinessRule(dto);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("policyId", saved.getId());
            response.put("message", msg("msg.policy.created"));
            if (!duplicateAutoRoles.isEmpty()) {
                response.put("warning",
                        "Auto-policies already exist for roles: " + String.join(", ", duplicateAutoRoles)
                        + ". Consider reviewing for potential duplicates.");
            }
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Failed to create quick policy", e);
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", e.getMessage()));
        }
    }

    // ==================== Resource Search API ====================

    @GetMapping("/api/resources")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> searchResourcesApi(
            @ModelAttribute ResourceSearchCriteria criteria,
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        Page<ManagedResource> page = resourceRegistryService.findResources(criteria, pageable);
        List<Map<String, Object>> content = page.getContent().stream().map(r -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", r.getId());
            m.put("resourceIdentifier", r.getResourceIdentifier());
            m.put("resourceType", r.getResourceType() != null ? r.getResourceType().name() : null);
            m.put("httpMethod", r.getHttpMethod() != null ? r.getHttpMethod().name() : null);
            m.put("friendlyName", r.getFriendlyName());
            m.put("status", r.getStatus() != null ? r.getStatus().name() : null);
            m.put("serviceOwner", r.getServiceOwner());
            m.put("sourceCodeLocation", r.getSourceCodeLocation());
            m.put("apiDocsUrl", r.getApiDocsUrl());
            m.put("description", r.getDescription());
            m.put("createdAt", r.getCreatedAt() != null ? r.getCreatedAt().toString() : null);
            return m;
        }).toList();
        return ResponseEntity.ok(Map.of(
                "content", content,
                "totalElements", page.getTotalElements(),
                "totalPages", page.getTotalPages(),
                "number", page.getNumber(),
                "size", page.getSize()
        ));
    }

    // ==================== AI Wizard API ====================

    @GetMapping("/api/stats")
    @ResponseBody
    public ResponseEntity<Map<String, Long>> getSystemStats() {
        try {
            long roleCount = roleService.getRoles().size();
            long permissionCount = permissionCatalogService.getAvailablePermissions().size();
            long conditionCount = conditionTemplateRepository.count();
            long policyCount = policyRepository.count();
            long resourceTotal = managedResourceRepository.count();
            long resourceNeedsDefinition = managedResourceRepository.countByStatus(ManagedResource.Status.NEEDS_DEFINITION);
            long resourcePermissionCreated = managedResourceRepository.countByStatus(ManagedResource.Status.PERMISSION_CREATED);
            long resourcePolicyConnected = managedResourceRepository.countByStatus(ManagedResource.Status.POLICY_CONNECTED);

            Map<String, Long> stats = new HashMap<>();
            stats.put("roleCount", roleCount);
            stats.put("permissionCount", permissionCount);
            stats.put("conditionCount", conditionCount);
            stats.put("policyCount", policyCount);
            stats.put("resourceTotal", resourceTotal);
            stats.put("resourceNeedsDefinition", resourceNeedsDefinition);
            stats.put("resourcePermissionCreated", resourcePermissionCreated);
            stats.put("resourcePolicyConnected", resourcePolicyConnected);
            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            log.error("Failed to load system stats", e);
            return ResponseEntity.ok(Map.of(
                    "roleCount", 0L, "permissionCount", 0L,
                    "conditionCount", 0L, "policyCount", 0L));
        }
    }

    @GetMapping("/api/policy-summaries")
    @ResponseBody
    public ResponseEntity<List<PolicySummaryDto>> getPolicySummaries() {
        try {
            List<PolicySummaryDto> summaries = policyService.getAllPolicies().stream()
                    .map(p -> PolicySummaryDto.builder()
                            .id(p.getId())
                            .name(p.getName())
                            .effect(p.getEffect() != null ? p.getEffect().name() : "ALLOW")
                            .build())
                    .collect(Collectors.toList());
            return ResponseEntity.ok(summaries);
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
            List<ConditionTemplate> templates = conditionTemplateRepository.findAll();
            List<ConditionTemplateDto> result = templates.stream()
                    .filter(ct -> keyword == null || keyword.isBlank()
                            || ct.getName().toLowerCase().contains(keyword.toLowerCase())
                            || (ct.getDescription() != null && ct.getDescription().toLowerCase().contains(keyword.toLowerCase())))
                    .map(ct -> ConditionTemplateDto.builder()
                            .id(ct.getId())
                            .name(ct.getName())
                            .description(ct.getDescription())
                            .category(ct.getCategory())
                            .build())
                    .collect(Collectors.toList());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Failed to load conditions", e);
            return ResponseEntity.ok(Collections.emptyList());
        }
    }

    // ==================== SpEL Permissions API ====================

    @GetMapping("/api/spel-permissions")
    @ResponseBody
    public ResponseEntity<List<Map<String, Object>>> getSpelPermissions(
            @RequestParam(required = false) String keyword) {
        try {
            List<SecuritySpel> spels = securitySpelRepository.search(keyword);
            List<Map<String, Object>> result = spels.stream().map(s -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", s.getId());
                m.put("name", s.getName());
                m.put("expression", s.getExpression());
                m.put("description", s.getDescription());
                m.put("category", s.getCategory());
                return m;
            }).toList();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Failed to load SpEL permissions", e);
            return ResponseEntity.ok(Collections.emptyList());
        }
    }

    // ==================== Manual Mode ====================

    @PostMapping("/create-policy")
    public String createPolicyFromCenter(@ModelAttribute PolicyDto policyDto, RedirectAttributes ra) {
        try {
            policyService.createPolicy(policyDto);
            ra.addFlashAttribute("message", msg("msg.policy.created"));
        } catch (Exception e) {
            log.error("Failed to create policy", e);
            ra.addFlashAttribute("errorMessage", msg("msg.policy.create.error", e.getMessage()));
        }
        return "redirect:/admin/policy-center?tab=list";
    }

    // ==================== Policy Validation API ====================

    @GetMapping("/api/validation-report")
    @ResponseBody
    public ResponseEntity<FullValidationReport> getValidationReport() {
        try {
            FullValidationReport report = policyValidationService.validateAll();
            return ResponseEntity.ok(report);
        } catch (Exception e) {
            log.error("Failed to generate validation report", e);
            return ResponseEntity.ok(new FullValidationReport(
                    0, "UNKNOWN", List.of(), List.of()));
        }
    }

    @PostMapping("/api/validate")
    @ResponseBody
    public ResponseEntity<PolicyValidationReport> validatePolicy(@RequestBody PolicyDto policyDto) {
        try {
            PolicyValidationReport report = policyService.validateBeforeCreate(policyDto);
            return ResponseEntity.ok(report);
        } catch (Exception e) {
            log.error("Failed to validate policy", e);
            return ResponseEntity.badRequest().body(new PolicyValidationReport(
                    List.of(), List.of(), false, e.getMessage()));
        }
    }

    @PostMapping("/api/validate-quick")
    @ResponseBody
    public ResponseEntity<PolicyValidationReport> validateQuickPolicy(
            @RequestBody QuickPolicyRequest request) {
        try {
            PolicyDto policyDto = PolicyDto.builder()
                    .name(request.getPolicyName())
                    .description(request.getDescription())
                    .effect(request.getEffect())
                    .priority(100)
                    .build();

            if ("MANUAL".equals(request.getSourceType())
                    && request.getManualTargetIdentifier() != null) {
                policyDto.setTargets(List.of(TargetDto.builder()
                        .targetType(request.getManualTargetType())
                        .targetIdentifier(request.getManualTargetIdentifier())
                        .httpMethod(request.getManualHttpMethod())
                        .targetOrder(request.getManualTargetOrder())
                        .build()));
            } else if (request.getPermissionIds() != null) {
                List<TargetDto> targets = new ArrayList<>();
                for (Long permId : request.getPermissionIds()) {
                    permissionRepository.findById(permId).ifPresent(perm -> {
                        ManagedResource mr = perm.getManagedResource();
                        if (mr != null) {
                            targets.add(TargetDto.builder()
                                    .targetType(mr.getResourceType().name())
                                    .targetIdentifier(mr.getResourceIdentifier())
                                    .httpMethod(mr.getHttpMethod() != null
                                            ? mr.getHttpMethod().name() : "ANY")
                                    .build());
                        }
                    });
                }
                policyDto.setTargets(targets);
            }

            PolicyValidationReport report = policyService.validateBeforeCreate(policyDto);
            return ResponseEntity.ok(report);
        } catch (Exception e) {
            log.error("Failed to validate quick policy", e);
            return ResponseEntity.badRequest().body(new PolicyValidationReport(
                    List.of(), List.of(), false, e.getMessage()));
        }
    }

    // ==================== AI Policy Validation API ====================

    @GetMapping("/api/{policyId}/ai-validation")
    @ResponseBody
    public ResponseEntity<AIPolicyValidationReport> validateAIPolicy(@PathVariable Long policyId) {
        try {
            return ResponseEntity.ok(policyService.validateAIPolicy(policyId));
        } catch (Exception e) {
            log.error("Failed to validate AI policy {}", policyId, e);
            return ResponseEntity.ok(new AIPolicyValidationReport(
                    List.of(), false, e.getMessage()));
        }
    }

    // ==================== Policy Simulation API ====================

    @PostMapping("/api/simulate")
    @ResponseBody
    public ResponseEntity<SimulationReport> simulate(@RequestBody SimulationRequest request) {
        try {
            return ResponseEntity.ok(policyService.simulate(
                    request.candidatePolicy(), request.testCases()));
        } catch (Exception e) {
            log.error("Failed to simulate policy", e);
            return ResponseEntity.ok(new SimulationReport(
                    List.of(), new SimulationReport.SimulationSummary(0, 0, 0, 0)));
        }
    }

    // ==================== Impact Analysis API ====================

    @PostMapping("/api/impact-analysis")
    @ResponseBody
    public ResponseEntity<PolicyImpactReport> analyzeImpact(
            @RequestBody PolicyDto policyDto) {
        try {
            return ResponseEntity.ok(policyService.analyzeImpact(policyDto));
        } catch (Exception e) {
            log.error("Failed to analyze policy impact", e);
            return ResponseEntity.ok(new PolicyImpactReport(
                    0, List.of(), List.of(),
                    new PolicyImpactReport.AccessChangeSummary(0, 0, 0)));
        }
    }

    // ==================== Policy Version API ====================

    @GetMapping("/api/{policyId}/versions")
    @ResponseBody
    public ResponseEntity<List<Map<String, Object>>> getVersions(@PathVariable Long policyId) {
        try {
            List<Map<String, Object>> versions = policyService.getVersions(policyId).stream()
                    .map(v -> {
                        Map<String, Object> m = new LinkedHashMap<>();
                        m.put("versionNumber", v.getVersionNumber());
                        m.put("changeType", v.getChangeType().name());
                        m.put("changedBy", v.getChangedBy());
                        m.put("changeReason", v.getChangeReason());
                        m.put("changedAt", v.getChangedAt() != null ? v.getChangedAt().toString() : null);
                        return m;
                    }).toList();
            return ResponseEntity.ok(versions);
        } catch (Exception e) {
            log.error("Failed to load versions for policy {}", policyId, e);
            return ResponseEntity.ok(List.of());
        }
    }

    @PostMapping("/api/{policyId}/rollback/{versionNumber}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> rollbackPolicy(
            @PathVariable Long policyId,
            @PathVariable int versionNumber,
            @RequestBody(required = false) Map<String, String> body) {
        try {
            String reason = body != null ? body.get("reason") : null;
            policyService.rollbackPolicy(policyId, versionNumber, reason);
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", msg("msg.policy.rollback.success")));
        } catch (Exception e) {
            log.error("Failed to rollback policy {} to version {}", policyId, versionNumber, e);
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", e.getMessage()));
        }
    }

    @GetMapping("/api/{policyId}/versions/compare")
    @ResponseBody
    public ResponseEntity<List<Map<String, String>>> compareVersions(
            @PathVariable Long policyId,
            @RequestParam int v1,
            @RequestParam int v2) {
        try {
            List<Map<String, String>> changes = policyVersionService.compareVersions(policyId, v1, v2);
            return ResponseEntity.ok(changes);
        } catch (Exception e) {
            log.error("Failed to compare versions for policy {}", policyId, e);
            return ResponseEntity.ok(List.of());
        }
    }

    // ==================== Policy Matrix API ====================

    @GetMapping("/api/matrix")
    @ResponseBody
    public ResponseEntity<PolicyMatrixReport> getMatrix(
            @RequestParam(required = false) String resourceFilter,
            @RequestParam(required = false) String roleFilter) {
        try {
            return ResponseEntity.ok(policyMatrixService.generateMatrix(resourceFilter, roleFilter));
        } catch (Exception e) {
            log.error("Failed to generate policy matrix", e);
            return ResponseEntity.ok(new PolicyMatrixReport(
                    List.of(), List.of(), List.of(), List.of()));
        }
    }
}
