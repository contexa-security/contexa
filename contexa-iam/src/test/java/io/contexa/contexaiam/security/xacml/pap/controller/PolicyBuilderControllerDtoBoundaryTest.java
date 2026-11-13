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
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.ConditionCompatibilityService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * D03: the policy builder screen is part of the policy center and has no template of its own. Its old addresses answered
 * with a missing template (500), and the builder for a resource with a 400 page when its parameters were missing; they
 * send the administrator to the policy center now and read nothing.
 */
@DisplayName("PolicyBuilderController old addresses")
class PolicyBuilderControllerDtoBoundaryTest {

    private final RoleService roleService = mock(RoleService.class);
    private final PermissionCatalogService permissionCatalogService = mock(PermissionCatalogService.class);
    private final ConditionTemplateRepository conditionTemplateRepository = mock(ConditionTemplateRepository.class);
    private final ManagedResourceRepository managedResourceRepository = mock(ManagedResourceRepository.class);
    private final PermissionService permissionService = mock(PermissionService.class);
    private final ConditionCompatibilityService conditionCompatibilityService = mock(ConditionCompatibilityService.class);

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.standaloneSetup(new PolicyBuilderController(roleService, permissionCatalogService,
                conditionTemplateRepository, managedResourceRepository, new ObjectMapper(), permissionService,
                conditionCompatibilityService)).build();
    }

    @Test
    @DisplayName("the builder sends the administrator to the creation tab of the policy center")
    void theBuilderSendsToTheCreationTab() throws Exception {
        mvc.perform(get("/contexa/admin/policy-builder"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/contexa/admin/policy-center?tab=create"));
    }

    @Test
    @DisplayName("the builder for a resource sends to the resources tab, with or without its parameters")
    void theBuilderForAResourceSendsToTheResourcesTab() throws Exception {
        mvc.perform(get("/contexa/admin/policy-builder/from-resource"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/contexa/admin/policy-center?tab=resources"));
        mvc.perform(post("/contexa/admin/policy-builder/from-resource")
                        .param("resourceId", "10").param("permissionId", "20"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/contexa/admin/policy-center?tab=resources"));

        verifyNoInteractions(roleService, permissionCatalogService, conditionTemplateRepository,
                managedResourceRepository, permissionService, conditionCompatibilityService);
    }
}
