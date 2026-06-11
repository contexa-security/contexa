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
package io.contexa.contexaiam.security.xacml.pap.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.domain.dto.ConditionTemplateDto;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.dto.RoleDto;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyBuilderDtos.PolicyBuilderConditionStatistics;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyBuilderDtos.PolicyBuilderResourceContext;
import io.contexa.contexacommon.entity.ManagedResource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin/policy-builder")
@RequiredArgsConstructor
@Slf4j
public class PolicyBuilderController {

    private final RoleService roleService;
    private final PermissionCatalogService permissionCatalogService;
    private final ConditionTemplateRepository conditionTemplateRepository;
    private final ManagedResourceRepository managedResourceRepository;
    private final ObjectMapper objectMapper;
    private final PermissionService permissionService;
    private final ConditionCompatibilityService conditionCompatibilityService;
    private static final Pattern SPEL_VARIABLE_PATTERN = Pattern.compile("#(\\w+)");

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
            model.addAttribute("resourceContext", PolicyBuilderResourceContext.defaultContext());
        }

        addContextAwareConditionsToModel(model);

        model.addAttribute("activePage", "policy-builder");
        return "admin/policy-builder";
    }

    private void addContextAwareConditionsToModel(Model model) {
        List<ConditionTemplate> allConditions = conditionTemplateRepository.findAll();

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
        model.addAttribute("conditionStatistics", PolicyBuilderConditionStatistics.from(allConditions));
    }
    private String enhanceConditionDescriptionV2(ConditionTemplate cond) {
        StringBuilder desc = new StringBuilder();

        if (StringUtils.hasText(cond.getDescription())) {
            desc.append(cond.getDescription());
        }

        if (cond.getClassification() != null) {
            switch (cond.getClassification()) {
                case UNIVERSAL -> desc.append(" [READY] (Available for immediate use)");
                case CONTEXT_DEPENDENT -> desc.append(" [REVIEW] (AI verification required)");
                case CUSTOM_COMPLEX -> desc.append(" [EXPERT] (Expert review required)");
            }
        }

        if (cond.getComplexityScore() != null) {
            desc.append(" [Complexity: ").append(cond.getComplexityScore()).append("/10]");
        }

        if (Boolean.TRUE.equals(cond.getApprovalRequired())) {
            desc.append(" Approval required");
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

    private ConditionTemplate findConditionById(List<ConditionTemplate> conditions, Long id) {
        return conditions.stream()
                .filter(c -> c.getId().equals(id))
                .findFirst()
                .orElse(new ConditionTemplate()); 
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
        model.addAttribute("conditionStatistics", PolicyBuilderConditionStatistics.from(compatibleConditions));

        Object parameterTypes;
        try {
            parameterTypes = objectMapper.readValue(resource.getParameterTypes(), Object.class);
        } catch (Exception e) {
            parameterTypes = Collections.emptyList();
        }
        model.addAttribute("resourceContext", PolicyBuilderResourceContext.fromResource(resource, parameterTypes));

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

}
