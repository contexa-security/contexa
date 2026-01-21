package io.contexa.contexaiam.security.xacml.pap.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.domain.dto.ConditionTemplateDto;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.dto.RoleDto;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import io.contexa.contexaiam.security.xacml.pap.dto.VisualPolicyDto;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyBuilderService;
import io.contexa.contexacommon.entity.ManagedResource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@RequestMapping("/admin/policy-builder")
@RequiredArgsConstructor
@Slf4j
public class PolicyBuilderController {

    private final PolicyBuilderService policyBuilderService;
    private final UserManagementService userManagementService;
    private final GroupService groupService;
    private final RoleService roleService;
    private final PermissionCatalogService permissionCatalogService;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final ObjectMapper objectMapper;
    private final PermissionService permissionService;
    private final ModelMapper modelMapper;
    private final ConditionCompatibilityService conditionCompatibilityService;
    private static final Pattern SPEL_VARIABLE_PATTERN = Pattern.compile("#(\\w+)");
    private static final Set<String> GLOBAL_CONTEXT_VARIABLES = Set.of("#authentication", "#request", "#ai");

    @GetMapping
    public String policyBuilder(Model model) {

        List<RoleDto> roleDtos = roleService.getRolesWithoutExpression().stream()
                .map(role -> RoleDto.builder()
                        .id(role.getId())
                        .roleName(role.getRoleName())
                        .roleDesc(role.getRoleDesc())
                        .build())
                .collect(Collectors.toList());

        List<PermissionDto> permissionDtos = permissionCatalogService.getAvailablePermissions().stream()
                .map(permission -> PermissionDto.builder()
                        .id(permission.getId())
                        .name(permission.getName())
                        .friendlyName(permission.getFriendlyName())
                        .description(permission.getDescription())
                        .targetType(permission.getTargetType())
                        .actionType(permission.getActionType())
                        .build())
                .collect(Collectors.toList());

        model.addAttribute("allRoles", roleDtos);
        model.addAttribute("allPermissions", permissionDtos);

        if (!model.containsAttribute("resourceContext")) {
            Map<String, Object> defaultContext = createDefaultResourceContext();
            model.addAttribute("resourceContext", defaultContext);
                    }

        addContextAwareConditionsToModel(model);

        model.addAttribute("activePage", "policy-builder");
        return "admin/policy-builder";
    }

    private Map<String, Object> createDefaultResourceContext() {
        Map<String, Object> context = new HashMap<>();
        context.put("resourceIdentifier", "GENERAL_POLICY");
        context.put("resourceType", "GENERAL");
        context.put("friendlyName", "일반 정책");
        context.put("description", "특정 리소스에 종속되지 않는 일반적인 정책");
        context.put("parameterTypes", "");
        context.put("returnType", "void");
        context.put("isDirectAccess", true);
        return context;
    }

    private void addContextAwareConditionsToModel(Model model) {
        List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();

        Map<ConditionTemplate.ConditionClassification, List<ConditionTemplate>> classifiedConditions =
                allConditions.stream()
                        .collect(Collectors.groupingBy(
                                cond -> cond.getClassification() != null ?
                                        cond.getClassification() : ConditionTemplate.ConditionClassification.UNIVERSAL));

        Map<ConditionTemplate.RiskLevel, List<ConditionTemplate>> riskGrouped =
                allConditions.stream()
                        .collect(Collectors.groupingBy(
                                cond -> cond.getRiskLevel() != null ?
                                        cond.getRiskLevel() : ConditionTemplate.RiskLevel.LOW));

        List<ConditionTemplateDto> conditionDtos = allConditions.stream().map(cond -> {
                    
                    Set<String> requiredVars = extractVariablesFromSpel(cond.getSpelTemplate());

                    String enhancedDescription = enhanceConditionDescriptionV2(cond);

                    boolean isActive = determineConditionActivation(cond, model);

                    return new ConditionTemplateDto(
                            cond.getId(),
                            cond.getName(),
                            enhancedDescription,
                            requiredVars,
                            isActive,
                            cond.getSpelTemplate()
                    );
                })
                .sorted((a, b) -> {
                    
                    ConditionTemplate condA = findConditionById(allConditions, a.id());
                    ConditionTemplate condB = findConditionById(allConditions, b.id());

                    int classOrder = getClassificationOrder(condA.getClassification()) -
                            getClassificationOrder(condB.getClassification());
                    if (classOrder != 0) return classOrder;

                    int complexityOrder = (condA.getComplexityScore() != null ? condA.getComplexityScore() : 1) -
                            (condB.getComplexityScore() != null ? condB.getComplexityScore() : 1);
                    if (complexityOrder != 0) return complexityOrder;

                    return a.name().compareTo(b.name());
                })
                .toList();

        model.addAttribute("allConditions", conditionDtos);
        model.addAttribute("conditionStatistics", calculateConditionStatistics(allConditions));
    }

    private String enhanceConditionDescription(ConditionTemplate cond) {
        StringBuilder desc = new StringBuilder();

        if (StringUtils.hasText(cond.getDescription())) {
            desc.append(cond.getDescription());
        }

        if (Boolean.TRUE.equals(cond.getIsAutoGenerated())) {
            if (Boolean.TRUE.equals(cond.getIsUniversal())) {
                desc.append(" 🤖🌍 (자동생성 범용)");
            } else {
                desc.append(" (자동생성)");
            }
        } else {
            desc.append(" 👤 (수동 설정)");
        }

        if (StringUtils.hasText(cond.getTemplateType())) {
            switch (cond.getTemplateType()) {
                case "universal" -> desc.append(" - 모든 메서드에 적용 가능");
                case "object_return" -> desc.append(" - 객체 반환 메서드용");
                case "id_parameter" -> desc.append(" - ID 파라미터 메서드용");
                case "ownership" -> desc.append(" - 소유권 검증용");
            }
        }

        return desc.toString();
    }

    private String enhanceConditionDescriptionV2(ConditionTemplate cond) {
        StringBuilder desc = new StringBuilder();

        if (StringUtils.hasText(cond.getDescription())) {
            desc.append(cond.getDescription());
        }

        if (cond.getClassification() != null) {
            switch (cond.getClassification()) {
                case UNIVERSAL -> desc.append(" 🟢 (즉시 사용 가능)");
                case CONTEXT_DEPENDENT -> desc.append(" 🟡 (AI 검증 필요)");
                case CUSTOM_COMPLEX -> desc.append(" 🔴 (전문가 검토)");
            }
        }

        if (cond.getComplexityScore() != null) {
            desc.append(" [복잡도: ").append(cond.getComplexityScore()).append("/10]");
        }

        if (Boolean.TRUE.equals(cond.getApprovalRequired())) {
            desc.append(" 승인필요");
        }

        return desc.toString();
    }

    private boolean determineConditionActivation(ConditionTemplate cond, Model model) {
        
        if (ConditionTemplate.ConditionClassification.UNIVERSAL.equals(cond.getClassification())) {
            return true;
        }

        if (Boolean.TRUE.equals(cond.getApprovalRequired())) {
            return false;
        }

        if (ConditionTemplate.ConditionClassification.CONTEXT_DEPENDENT.equals(cond.getClassification())) {
            return model.containsAttribute("resourceContext");
        }

        return true;
    }

    private int getClassificationOrder(ConditionTemplate.ConditionClassification classification) {
        if (classification == null) return 2;
        return switch (classification) {
            case UNIVERSAL -> 1;
            case CONTEXT_DEPENDENT -> 2;
            case CUSTOM_COMPLEX -> 3;
        };
    }

    private Map<String, Object> calculateConditionStatistics(List<ConditionTemplate> conditions) {
        Map<String, Object> stats = new HashMap<>();

        Map<ConditionTemplate.ConditionClassification, Long> byClassification =
                conditions.stream()
                        .collect(Collectors.groupingBy(
                                c -> c.getClassification() != null ? c.getClassification() : ConditionTemplate.ConditionClassification.UNIVERSAL,
                                Collectors.counting()));

        Map<ConditionTemplate.RiskLevel, Long> byRiskLevel =
                conditions.stream()
                        .collect(Collectors.groupingBy(
                                c -> c.getRiskLevel() != null ? c.getRiskLevel() : ConditionTemplate.RiskLevel.LOW,
                                Collectors.counting()));

        stats.put("total", conditions.size());
        stats.put("byClassification", byClassification);
        stats.put("byRiskLevel", byRiskLevel);
        stats.put("averageComplexity", conditions.stream()
                .mapToInt(c -> c.getComplexityScore() != null ? c.getComplexityScore() : 1)
                .average().orElse(0.0));
        stats.put("requireApproval", conditions.stream()
                .mapToLong(c -> Boolean.TRUE.equals(c.getApprovalRequired()) ? 1 : 0)
                .sum());

        return stats;
    }

    private ConditionTemplate findConditionById(List<ConditionTemplate> conditions, Long id) {
        return conditions.stream()
                .filter(c -> c.getId().equals(id))
                .findFirst()
                .orElse(new ConditionTemplate()); 
    }

    private Set<String> getAvailableTypesFromModel(Model model) {
        
        Set<String> types = new HashSet<>(GLOBAL_CONTEXT_VARIABLES);

        if (model.containsAttribute("resourceContext")) {
            Map<String, Object> rc = (Map<String, Object>) model.getAttribute("resourceContext");
            if (rc != null) {
                Object resourceSpecificVarsObj = rc.get("availableVariables");

                if (resourceSpecificVarsObj instanceof Collection) {
                    
                    types.addAll((Collection<String>) resourceSpecificVarsObj);
                }

                Object returnTypeObj = rc.get("returnObjectType");
                if (returnTypeObj != null) {
                    types.add(returnTypeObj.toString());
                }
            }
        }
        return types;
    }

    private Set<String> extractVariablesFromSpel(String spelTemplate) {
        Set<String> variables = new HashSet<>();
        if (spelTemplate == null) return variables;
        Matcher matcher = SPEL_VARIABLE_PATTERN.matcher(spelTemplate);
        while (matcher.find()) {
            variables.add(matcher.group()); 
        }
        return variables;
    }

    @RequestMapping(value = "/from-resource", method = {RequestMethod.GET, RequestMethod.POST})
    public String policyBuilderFromResource(
            @RequestParam Long resourceId,
            @RequestParam Long permissionId,
            Model model) {

        ManagedResource resource = managedResourceRepository.findById(resourceId)
                .orElseThrow(() -> new IllegalArgumentException("Resource not found"));

        List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();
        List<ConditionTemplate> compatibleConditions = conditionCompatibilityService.getCompatibleConditions(resource, allConditions);

        List<ConditionTemplateDto> conditionDtos = compatibleConditions.stream()
                .map(cond -> {
                    Set<String> requiredVars = extractVariablesFromSpel(cond.getSpelTemplate());
                    String enhancedDescription = enhanceConditionDescriptionV2(cond);
                    
                    return new ConditionTemplateDto(
                            cond.getId(),
                            cond.getName(),
                            enhancedDescription,
                            requiredVars,
                            true, 
                            cond.getSpelTemplate()
                    );
                })
                .sorted((a, b) -> {
                    
                    ConditionTemplate condA = findConditionById(compatibleConditions, a.id());
                    ConditionTemplate condB = findConditionById(compatibleConditions, b.id());
                    
                    int classificationOrder1 = getClassificationOrder(condA.getClassification());
                    int classificationOrder2 = getClassificationOrder(condB.getClassification());
                    if (classificationOrder1 != classificationOrder2) {
                        return Integer.compare(classificationOrder1, classificationOrder2);
                    }
                    return a.name().compareTo(b.name());
                })
                .toList();

        model.addAttribute("allConditions", conditionDtos);
        model.addAttribute("conditionStatistics", calculateConditionStatistics(compatibleConditions));

        Map<String, Object> resourceContext = new HashMap<>();
        resourceContext.put("resourceIdentifier", resource.getResourceIdentifier());
        try {
            resourceContext.put("parameterTypes", objectMapper.readValue(resource.getParameterTypes(), new TypeReference<>() {}));
        } catch (Exception e) {
            resourceContext.put("parameterTypes", Collections.emptyList());
        }
        resourceContext.put("returnObjectType", resource.getReturnType());
        model.addAttribute("resourceContext", resourceContext);

        permissionService.getPermission(permissionId)
                .ifPresent(permission -> {
                    PermissionDto permissionDto = PermissionDto.builder()
                            .id(permission.getId())
                            .name(permission.getName())
                            .friendlyName(permission.getFriendlyName())
                            .description(permission.getDescription())
                            .build();
                    model.addAttribute("preselectedPermission", permissionDto);
                });

        List<RoleDto> roleDtos = roleService.getRolesWithoutExpression().stream()
                .map(role -> RoleDto.builder()
                        .id(role.getId())
                        .roleName(role.getRoleName())
                        .roleDesc(role.getRoleDesc())
                        .build())
                .collect(Collectors.toList());

        List<PermissionDto> permissionDtos = permissionCatalogService.getAvailablePermissions().stream()
                .map(permission -> PermissionDto.builder()
                        .id(permission.getId())
                        .name(permission.getName())
                        .friendlyName(permission.getFriendlyName())
                        .description(permission.getDescription())
                        .targetType(permission.getTargetType())
                        .actionType(permission.getActionType())
                        .build())
                .collect(Collectors.toList());

        model.addAttribute("allRoles", roleDtos);
        model.addAttribute("allPermissions", permissionDtos);
        model.addAttribute("activePage", "policy-builder");
        
        return "admin/policy-builder";
    }

    @PostMapping("/api/build")
    public ResponseEntity<Policy> buildPolicy(@RequestBody VisualPolicyDto visualPolicyDto) {
        Policy createdPolicy = policyBuilderService.buildPolicyFromVisualComponents(visualPolicyDto);
        return ResponseEntity.ok(createdPolicy);
    }
}