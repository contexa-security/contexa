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
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.metadata.service.PermissionCatalogService;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("PolicyBuilderController DTO boundary")
class PolicyBuilderControllerDtoBoundaryTest {

    @Mock
    private RoleService roleService;

    @Mock
    private PermissionCatalogService permissionCatalogService;

    @Mock
    private ConditionTemplateRepository conditionTemplateRepository;

    @Mock
    private ManagedResourceRepository managedResourceRepository;

    @Mock
    private PermissionService permissionService;

    @Mock
    private ConditionCompatibilityService conditionCompatibilityService;

    @Test
    @DisplayName("default policy-builder model uses typed objects instead of Map")
    void defaultPolicyBuilderModelUsesTypedObjectsInsteadOfMap() {
        when(roleService.getRolesWithoutExpression()).thenReturn(List.of());
        when(permissionCatalogService.getAvailablePermissions()).thenReturn(List.of());
        when(conditionTemplateRepository.findAll()).thenReturn(List.of(
                condition(1L, "universal", ConditionTemplate.ConditionClassification.UNIVERSAL)));

        Model model = new ExtendedModelMap();
        String viewName = newController().policyBuilder(model);

        assertThat(viewName).isEqualTo("admin/policy-builder");
        Object resourceContext = model.asMap().get("resourceContext");
        Object conditionStatistics = model.asMap().get("conditionStatistics");

        assertThat(resourceContext).isNotInstanceOf(Map.class);
        assertThat(conditionStatistics).isNotInstanceOf(Map.class);

        BeanWrapperImpl context = new BeanWrapperImpl(resourceContext);
        assertThat(context.getPropertyValue("resourceIdentifier")).isEqualTo("GENERAL_POLICY");
        assertThat(context.getPropertyValue("resourceType")).isEqualTo("GENERAL");
        assertThat(context.getPropertyValue("isDirectAccess")).isEqualTo(true);

        BeanWrapperImpl statistics = new BeanWrapperImpl(conditionStatistics);
        assertThat(statistics.getPropertyValue("total")).isEqualTo(1);
        assertThat(statistics.getPropertyValue("requireApproval")).isEqualTo(0L);
    }

    @Test
    @DisplayName("resource policy-builder model uses typed resource context instead of Map")
    void resourcePolicyBuilderModelUsesTypedResourceContextInsteadOfMap() {
        ManagedResource resource = ManagedResource.builder()
                .id(10L)
                .resourceIdentifier("UserController.list")
                .resourceType(ManagedResource.ResourceType.METHOD)
                .friendlyName("User list")
                .parameterTypes("[\"java.lang.String\"]")
                .returnType("java.lang.String")
                .build();
        ConditionTemplate condition = condition(
                1L,
                "context",
                ConditionTemplate.ConditionClassification.CONTEXT_DEPENDENT);

        when(managedResourceRepository.findById(10L)).thenReturn(Optional.of(resource));
        when(conditionTemplateRepository.findAll()).thenReturn(List.of(condition));
        when(conditionCompatibilityService.getCompatibleConditions(resource, List.of(condition)))
                .thenReturn(List.of(condition));
        when(permissionService.getPermission(20L)).thenReturn(Optional.empty());
        when(roleService.getRolesWithoutExpression()).thenReturn(List.of());
        when(permissionCatalogService.getAvailablePermissions()).thenReturn(List.of());

        Model model = new ExtendedModelMap();
        String viewName = newController().policyBuilderFromResource(10L, 20L, model);

        assertThat(viewName).isEqualTo("admin/policy-builder");
        Object resourceContext = model.asMap().get("resourceContext");

        assertThat(resourceContext).isNotInstanceOf(Map.class);
        BeanWrapperImpl context = new BeanWrapperImpl(resourceContext);
        assertThat(context.getPropertyValue("resourceIdentifier")).isEqualTo("UserController.list");
        assertThat(context.getPropertyValue("parameterTypes")).isEqualTo(List.of("java.lang.String"));
        assertThat(context.getPropertyValue("returnObjectType")).isEqualTo("java.lang.String");
    }

    private PolicyBuilderController newController() {
        return new PolicyBuilderController(
                roleService,
                permissionCatalogService,
                conditionTemplateRepository,
                managedResourceRepository,
                new ObjectMapper(),
                permissionService,
                conditionCompatibilityService);
    }

    private static ConditionTemplate condition(
            Long id,
            String name,
            ConditionTemplate.ConditionClassification classification) {
        return ConditionTemplate.builder()
                .id(id)
                .name(name)
                .description(name + " description")
                .spelTemplate("true")
                .classification(classification)
                .complexityScore(1)
                .approvalRequired(false)
                .build();
    }
}
