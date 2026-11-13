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
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * The old policy builder addresses. The builder screen is part of the policy center now and has no template of its
 * own, so the addresses send the administrator there instead of failing with a missing template (D03): the builder to
 * the creation tab, the builder for a resource to the resources tab, where a resource is defined and its policy made.
 */
@Controller
@RequestMapping("/contexa/admin/policy-builder")
@Slf4j
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class PolicyBuilderController {

    static final String POLICY_CENTER_CREATE = "redirect:/contexa/admin/policy-center?tab=create";
    static final String POLICY_CENTER_RESOURCES = "redirect:/contexa/admin/policy-center?tab=resources";

    /** The services of the screen the policy center replaced; the auto-configuration still passes them. */
    public PolicyBuilderController(RoleService roleService, PermissionCatalogService permissionCatalogService,
                                   ConditionTemplateRepository conditionTemplateRepository,
                                   ManagedResourceRepository managedResourceRepository,
                                   @Qualifier("contexaObjectMapper") ObjectMapper objectMapper,
                                   PermissionService permissionService,
                                   ConditionCompatibilityService conditionCompatibilityService) {
    }

    @GetMapping
    public String policyBuilder() {
        return POLICY_CENTER_CREATE;
    }

    @RequestMapping(value = "/from-resource", method = {RequestMethod.GET, RequestMethod.POST})
    public String policyBuilderFromResource() {
        return POLICY_CENTER_RESOURCES;
    }
}
