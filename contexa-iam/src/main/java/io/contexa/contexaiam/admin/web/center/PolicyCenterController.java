package io.contexa.contexaiam.admin.web.center;

import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.center.dto.ConditionTemplateDto;
import io.contexa.contexaiam.admin.web.center.dto.PolicySummaryDto;
import io.contexa.contexaiam.admin.web.center.dto.QuickPolicyRequest;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.domain.dto.BusinessPolicyDto;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyEnrichmentService;
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
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
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
import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import org.springframework.security.core.context.SecurityContextHolder;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexaiam.admin.web.center.dto.BatchCreateRequest;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyRule;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.domain.entity.policy.PolicyVersion;
import org.springframework.dao.DataIntegrityViolationException;
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
    private final PolicyEnrichmentService policyEnrichmentService;
    private final PolicyVersionService policyVersionService;
    private final PolicyMatrixService policyMatrixService;
    private final PolicyCombiningProperties policyCombiningProperties;
    private final CustomDynamicAuthorizationManager authorizationManager;
    private final CentralAuditFacade centralAuditFacade;

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
            @RequestParam(required = false) String approvalStatus,
            @RequestParam(required = false) Boolean activeFilter,
            @RequestParam(required = false, defaultValue = "0") int policyPage,
            Model model) {

        model.addAttribute("activePage", "policy-center");
        model.addAttribute("activeTab", tab);
        model.addAttribute("combiningAlgorithm", policyCombiningProperties.getCombiningAlgorithm().name());

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
            Policy.ApprovalStatus approvalStatusEnum = null;
            if (approvalStatus != null && !approvalStatus.isBlank()) {
                try { approvalStatusEnum = Policy.ApprovalStatus.valueOf(approvalStatus); } catch (IllegalArgumentException ignored) {}
            }
            Page<Policy> policyPageResult = policyService.searchPolicies(policyKeyword, approvalStatusEnum, activeFilter, policyPageable);
            model.addAttribute("policyPage", policyPageResult);
            model.addAttribute("policyKeyword", policyKeyword);
            model.addAttribute("approvalStatusFilter", approvalStatus);
            model.addAttribute("activeFilter", activeFilter);

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
            synchronizeResourcePolicyStatus(); // bidirectional sync after refresh
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
                    .map(io.contexa.contexaiam.resource.util.ResourceTargetKey::ofPolicyTarget)
                    .collect(java.util.stream.Collectors.toSet());

            // Downgrade: POLICY_CONNECTED -> PERMISSION_CREATED if no policy targets
            managedResourceRepository.findByStatusInWithPermission(
                    List.of(ManagedResource.Status.POLICY_CONNECTED)
            ).forEach(resource -> {
                String key = io.contexa.contexaiam.resource.util.ResourceTargetKey.ofResource(resource);
                if (!allPolicyTargets.contains(key)) {
                    resource.setStatus(ManagedResource.Status.PERMISSION_CREATED);
                    managedResourceRepository.save(resource);
                }
            });

            // Upgrade: PERMISSION_CREATED -> POLICY_CONNECTED if policy targets exist
            managedResourceRepository.findByStatusInWithPermission(
                    List.of(ManagedResource.Status.PERMISSION_CREATED)
            ).forEach(resource -> {
                String key = io.contexa.contexaiam.resource.util.ResourceTargetKey.ofResource(resource);
                if (allPolicyTargets.contains(key)) {
                    resource.setStatus(ManagedResource.Status.POLICY_CONNECTED);
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
            dto.setCrudPermissions(request.getCrudPermissions());
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
                        msg("msg.policy.auto.duplicate.warning", String.join(", ", duplicateAutoRoles)));
            }
            return ResponseEntity.ok(response);
        } catch (DataIntegrityViolationException e) {
            log.error("Duplicate policy name", e);
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", msg("msg.policy.name.duplicate")));
        } catch (Exception e) {
            log.error("Failed to create quick policy", e);
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", msg("msg.policy.create.error", e.getMessage())));
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
            String pattern = (keyword != null && !keyword.isBlank()) ? "%" + keyword.toLowerCase() + "%" : null;
            List<SecuritySpel> spels = securitySpelRepository.search(pattern);
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
        } catch (DataIntegrityViolationException e) {
            log.error("Duplicate policy name", e);
            ra.addFlashAttribute("errorMessage", msg("msg.policy.name.duplicate"));
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

    // ==================== Reset Resource Policy Status API ====================

    @PostMapping("/api/reset-policy-status")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> resetPolicyStatus(@RequestBody List<Long> resourceIds) {
        if (resourceIds == null || resourceIds.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("success", false,
                    "message", msg("msg.policy.validation.target.required")));
        }
        int updated = 0;
        for (Long id : resourceIds) {
            try {
                managedResourceRepository.findById(id).ifPresent(resource -> {
                    if (resource.getStatus() != ManagedResource.Status.PERMISSION_CREATED) {
                        return;
                    }
                    // Delete linked permission
                    Permission perm = resource.getPermission();
                    if (perm != null) {
                        resource.setPermission(null);
                        managedResourceRepository.save(resource);
                        managedResourceRepository.flush();
                        permissionRepository.deleteById(perm.getId());
                        permissionRepository.flush();
                    }
                    // Reset status
                    resource.setStatus(ManagedResource.Status.NEEDS_DEFINITION);
                    managedResourceRepository.save(resource);
                });
                updated++;
            } catch (Exception e) {
                log.error("Failed to reset resource status: {}", id, e);
            }
        }
        return ResponseEntity.ok(Map.of("success", true, "updated", updated));
    }

    // ==================== Batch Policy Creation API ====================

    @PostMapping("/api/batch-create")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> batchCreatePolicies(
            @RequestBody BatchCreateRequest request) {
        try {
            // Input validation
            if (request.getItems() == null || request.getItems().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("success", false,
                        "message", msg("msg.policy.validation.target.required")));
            }
            Set<Long> roleIds = request.getRoleIds();
            List<Role> roles = new ArrayList<>();
            if (roleIds != null) {
                for (Long rid : roleIds) {
                    try { roles.add(roleService.getRole(rid)); } catch (Exception ignored) {}
                }
            }
            if (roles.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("success", false,
                        "message", msg("msg.policy.batch.role.required")));
            }

            String roleCondition = roles.stream()
                    .map(r -> String.format("hasAuthority('%s')", r.getRoleName()))
                    .collect(Collectors.joining(" or "));
            String allRoleNames = roles.stream().map(Role::getRoleName)
                    .collect(Collectors.joining("_"));

            List<Policy> allExisting = policyRepository.findAllWithDetails();
            List<Policy> batchCreated = new ArrayList<>();
            List<Map<String, Object>> results = new ArrayList<>();

            for (var item : request.getItems()) {
                try {
                    // Validate CRUD
                    if (item.getCrudPermissions() == null || item.getCrudPermissions().isEmpty()) {
                        results.add(Map.of("resourceIdentifier",
                                item.getResourceIdentifier() != null ? item.getResourceIdentifier() : "unknown",
                                "status", "SKIPPED", "reason", msg("msg.policy.batch.no.crud")));
                        continue;
                    }

                    // Build SpEL condition (sorted for deterministic expression)
                    String crudCondition = new TreeSet<>(item.getCrudPermissions()).stream()
                            .map(c -> String.format("hasAuthority('%s')", c))
                            .collect(Collectors.joining(" or "));
                    String spelExpr = "(" + roleCondition + ") and (" + crudCondition + ")";

                    // Auto-generate unique policy name (sorted for deterministic naming)
                    String crud = new TreeSet<>(item.getCrudPermissions()).stream()
                            .collect(Collectors.joining("_"));
                    String resPath = item.getResourceIdentifier() != null
                            ? item.getResourceIdentifier().replaceAll("[/{}]", "_").replaceAll("^_+|_+$", "").toUpperCase() : "";
                    String rawName = request.getEffect().name() + "_" + allRoleNames + "_" + crud + "_" + resPath;
                    String policyName = rawName.replaceAll("_+", "_");
                    if (policyName.length() > 200) policyName = policyName.substring(0, 200);

                    Policy candidate = Policy.builder()
                            .name(policyName)
                            .description(item.getResourceIdentifier())
                            .effect(request.getEffect())
                            .priority(100)
                            .source(Policy.PolicySource.MANUAL)
                            .approvalStatus(Policy.ApprovalStatus.NOT_REQUIRED)
                            .isActive(true)
                            .build();

                    // Add target
                    var target = PolicyTarget.builder()
                            .targetType(item.getResourceType() != null ? item.getResourceType() : "URL")
                            .targetIdentifier(item.getResourceIdentifier())
                            .httpMethod(item.getHttpMethod() != null ? item.getHttpMethod() : "ANY")
                            .sourceType("RESOURCE")
                            .build();
                    candidate.addTarget(target);

                    // Add rule with condition
                    var rule = PolicyRule.builder().build();
                    var condition = PolicyCondition.builder()
                            .expression(spelExpr).build();
                    rule.addCondition(condition);
                    candidate.addRule(rule);

                    // Validate against existing + batch-created policies (2-arg overload)
                    List<Policy> checkAgainst = new ArrayList<>(allExisting);
                    checkAgainst.addAll(batchCreated);
                    var validationReport = policyValidationService.validate(candidate, checkAgainst);
                    if (!validationReport.canCreate()) {
                        results.add(Map.of("resourceIdentifier", item.getResourceIdentifier(),
                                "status", "SKIPPED", "reason",
                                validationReport.blockedReason() != null ? validationReport.blockedReason() : msg("msg.policy.validation.blocked.critical")));
                        continue;
                    }

                    policyEnrichmentService.enrichPolicyWithFriendlyDescription(candidate);
                    Policy saved = policyRepository.save(candidate);

                    // Version history
                    policyVersionService.createVersion(saved,
                            PolicyVersion.ChangeType.CREATED, null);

                    // Update resource status
                    if (item.getPermissionId() != null) {
                        permissionRepository.findById(item.getPermissionId()).ifPresent(perm -> {
                            var resource = perm.getManagedResource();
                            if (resource != null && resource.getStatus() == ManagedResource.Status.PERMISSION_CREATED) {
                                resource.setStatus(ManagedResource.Status.POLICY_CONNECTED);
                                managedResourceRepository.save(resource);
                            }
                        });
                    }

                    batchCreated.add(saved);
                    results.add(Map.of("resourceIdentifier", item.getResourceIdentifier(),
                            "status", "CREATED", "policyId", saved.getId(), "policyName", saved.getName()));

                } catch (DataIntegrityViolationException e) {
                    results.add(Map.of("resourceIdentifier",
                            item.getResourceIdentifier() != null ? item.getResourceIdentifier() : "unknown",
                            "status", "ERROR", "reason", msg("msg.policy.name.duplicate")));
                } catch (Exception e) {
                    log.error("Batch item failed: {}", item.getResourceIdentifier(), e);
                    results.add(Map.of("resourceIdentifier",
                            item.getResourceIdentifier() != null ? item.getResourceIdentifier() : "unknown",
                            "status", "ERROR", "reason", msg("msg.policy.create.error", e.getMessage())));
                }
            }

            // Reload authorization system once after all batch items processed
            if (!batchCreated.isEmpty()) {
                authorizationManager.reload();
                try {
                    String principal = "SYSTEM";
                    var auth = SecurityContextHolder.getContext().getAuthentication();
                    if (auth != null && auth.getName() != null) principal = auth.getName();
                    centralAuditFacade.recordAsync(AuditRecord.builder()
                            .eventCategory(AuditEventCategory.POLICY_CREATED)
                            .principalName(principal)
                            .resourceIdentifier("batch-create")
                            .eventSource("IAM")
                            .action("BATCH_POLICY_CREATED")
                            .decision("SUCCESS")
                            .outcome("SUCCESS")
                            .details(Map.of(
                                    "created", batchCreated.size(),
                                    "total", request.getItems().size(),
                                    "roles", allRoleNames,
                                    "source", "MANUAL"))
                            .build());
                } catch (Exception ae) {
                    log.error("Failed to audit batch policy creation", ae);
                }
            }

            return ResponseEntity.ok(Map.of("success", true, "results", results,
                    "created", batchCreated.size(), "total", request.getItems().size()));
        } catch (Exception e) {
            log.error("Batch policy creation failed", e);
            return ResponseEntity.badRequest().body(Map.of("success", false,
                    "message", msg("msg.policy.create.error", e.getMessage())));
        }
    }

    // ==================== CRUD Migration API ====================

    /**
     * Migrate existing policy expressions from per-resource permissions (URL_DELETE_USERS)
     * to common CRUD permissions (DELETE). One-time migration endpoint.
     */
    /**
     * Auto-migrate old policy expressions on server startup.
     * Converts hasAuthority('URL_xxx') to hasAuthority('CRUD') and regenerates friendlyDescription.
     */
    @org.springframework.context.event.EventListener(org.springframework.boot.context.event.ApplicationReadyEvent.class)
    public void autoMigratePolicyExpressions() {
        try {
            int migrated = executePolicyMigration();
            if (migrated > 0) {
                log.error("[migration] Auto-migrated {} policy expressions from URL_/METHOD_ to CRUD", migrated);
            }
        } catch (Exception e) {
            log.error("[migration] Auto-migration failed", e);
        }
    }

    @PostMapping("/api/migrate-to-crud")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> migratePolicyExpressionsToCrud() {
        try {
            int migrated = executePolicyMigration();
            return ResponseEntity.ok(Map.of("success", true, "migrated", migrated));
        } catch (Exception e) {
            log.error("Failed to migrate policy expressions", e);
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", e.getMessage()));
        }
    }

    private int executePolicyMigration() {
        int migrated = 0;
        List<Policy> allPolicies = policyRepository.findAllWithDetails();
        for (Policy policy : allPolicies) {
            boolean changed = false;
            for (var rule : policy.getRules()) {
                for (var condition : rule.getConditions()) {
                    String expr = condition.getExpression();
                    String newExpr = migrateExpressionToCrud(expr);
                    if (!expr.equals(newExpr)) {
                        condition.setExpression(newExpr);
                        changed = true;
                    }
                }
            }
            if (changed) {
                policyEnrichmentService.enrichPolicyWithFriendlyDescription(policy);
                policyRepository.save(policy);
                migrated++;
            }
        }
        return migrated;
    }

    private String migrateExpressionToCrud(String expression) {
        // Replace hasAuthority('URL_xxx') or hasAuthority('METHOD_xxx') with CRUD equivalent
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("hasAuthority\\('(URL_|METHOD_)([^']*)'\\)");
        java.util.regex.Matcher matcher = pattern.matcher(expression);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String permName = matcher.group(1) + matcher.group(2);
            String crud = resolvePermissionToCrud(permName);
            matcher.appendReplacement(sb, "hasAuthority('" + crud + "')");
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private String resolvePermissionToCrud(String permissionName) {
        // Look up permission -> managed resource -> http method -> CRUD
        return permissionRepository.findByName(permissionName)
                .map(perm -> {
                    var resource = perm.getManagedResource();
                    if (resource != null && resource.getHttpMethod() != null) {
                        return switch (resource.getHttpMethod().name()) {
                            case "GET" -> "READ";
                            case "POST" -> "WRITE";
                            case "PUT", "PATCH" -> "UPDATE";
                            case "DELETE" -> "DELETE";
                            default -> "READ";
                        };
                    }
                    // Fallback: infer from permission name
                    String upper = permissionName.toUpperCase();
                    if (upper.contains("DELETE") || upper.contains("REMOVE")) return "DELETE";
                    if (upper.contains("CREATE") || upper.contains("SAVE") || upper.contains("ADD") || upper.contains("POST")) return "WRITE";
                    if (upper.contains("UPDATE") || upper.contains("EDIT") || upper.contains("MODIFY") || upper.contains("PUT")) return "UPDATE";
                    return "READ";
                })
                .orElse("READ");
    }

    /**
     * Cleanup old auto-created per-resource permissions (URL_*, METHOD_*).
     * Should be run AFTER migrate-to-crud to remove orphaned permissions.
     */
    @PostMapping("/api/cleanup-old-permissions")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> cleanupOldAutoCreatedPermissions() {
        try {
            List<Permission> oldPerms = permissionRepository.findAll().stream()
                    .filter(p -> p.isAutoCreated()
                            && p.getName() != null
                            && (p.getName().startsWith("URL_") || p.getName().startsWith("METHOD_")))
                    .toList();

            List<Long> deletedIds = new ArrayList<>();
            for (Permission perm : oldPerms) {
                // Unlink from managed resource
                if (perm.getManagedResource() != null) {
                    perm.setManagedResource(null);
                }
                deletedIds.add(perm.getId());
            }

            if (!deletedIds.isEmpty()) {
                permissionRepository.saveAll(oldPerms);
                permissionRepository.flush();
                permissionRepository.deleteAllByIds(deletedIds);
                permissionRepository.flush();
            }

            return ResponseEntity.ok(Map.of("success", true, "deleted", deletedIds.size()));
        } catch (Exception e) {
            log.error("Failed to cleanup old permissions", e);
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", e.getMessage()));
        }
    }

    // ==================== Impact Analysis API ====================

    @PostMapping("/api/impact-analysis")
    @ResponseBody
    public ResponseEntity<?> analyzeImpact(
            @RequestBody PolicyDto policyDto) {
        try {
            return ResponseEntity.ok(policyService.analyzeImpact(policyDto));
        } catch (Exception e) {
            log.error("Failed to analyze policy impact", e);
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", msg("msg.policy.impact.failed", e.getMessage())));
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

    @GetMapping("/api/{policyId}/versions/{versionNumber}")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getVersionSnapshot(
            @PathVariable Long policyId, @PathVariable int versionNumber) {
        try {
            var version = policyVersionService.getVersion(policyId, versionNumber)
                    .orElseThrow(() -> new IllegalArgumentException("Version not found"));
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("versionNumber", version.getVersionNumber());
            result.put("changeType", version.getChangeType().name());
            result.put("changedBy", version.getChangedBy());
            result.put("changeReason", version.getChangeReason());
            result.put("changedAt", version.getChangedAt() != null ? version.getChangedAt().toString() : null);
            result.put("snapshot", version.getSnapshotJson());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Failed to load version snapshot for policy {}, version {}", policyId, versionNumber, e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
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
