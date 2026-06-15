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
package io.contexa.contexaiam.admin.web.center.service;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexaiam.admin.web.center.dto.PolicyResourceSearchRequest;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pdp.combining.CombiningAlgorithm;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("PolicyCenterPageService")
class PolicyCenterPageServiceTest {

    @Mock private ResourceRegistryService resourceRegistryService;
    @Mock private PolicyService policyService;
    @Mock private PolicyCombiningProperties policyCombiningProperties;

    @InjectMocks
    private PolicyCenterPageService service;

    @Test
    @DisplayName("should populate policy center model with resources, policies, and properties")
    void populateModel() {
        Model model = new ConcurrentModel();
        PolicyResourceSearchRequest criteria = new PolicyResourceSearchRequest();

        when(policyCombiningProperties.getCombiningAlgorithm()).thenReturn(CombiningAlgorithm.FIRST_APPLICABLE);

        Page<ManagedResource> resourcePage = new PageImpl<>(List.of(new ManagedResource()));
        when(resourceRegistryService.findResources(any(), any())).thenReturn(resourcePage);
        when(resourceRegistryService.getAllServiceOwners()).thenReturn(Set.of("IAM"));

        Page<Policy> policyPage = new PageImpl<>(List.of(new Policy()));
        when(policyService.searchPolicies(eq("pKeyword"), eq(Policy.ApprovalStatus.PENDING), eq(true), any()))
                .thenReturn(policyPage);

        service.populatePolicyCenterModel(
                model,
                "tab-1",
                criteria,
                PageRequest.of(0, 10),
                "pKeyword",
                "PENDING",
                true,
                0
        );

        assertThat(model.getAttribute("activePage")).isEqualTo("policy-center");
        assertThat(model.getAttribute("activeTab")).isEqualTo("tab-1");
        assertThat(model.getAttribute("combiningAlgorithm")).isEqualTo("FIRST_APPLICABLE");
        assertThat(model.getAttribute("resourcePage")).isEqualTo(resourcePage);
        assertThat((Set<String>) model.getAttribute("serviceOwners")).contains("IAM");
        assertThat(model.getAttribute("policyPage")).isEqualTo(policyPage);
        assertThat(model.getAttribute("policyKeyword")).isEqualTo("pKeyword");
    }

    @Test
    @DisplayName("should populate policy center error model with empty pages and error message")
    void populateErrorModel() {
        Model model = new ConcurrentModel();
        PolicyResourceSearchRequest criteria = new PolicyResourceSearchRequest();

        when(policyCombiningProperties.getCombiningAlgorithm()).thenReturn(CombiningAlgorithm.DENY_OVERRIDES);

        service.populatePolicyCenterErrorModel(model, "tab-2", criteria, "Something went wrong");

        assertThat(model.getAttribute("activePage")).isEqualTo("policy-center");
        assertThat(model.getAttribute("activeTab")).isEqualTo("tab-2");
        assertThat(model.getAttribute("combiningAlgorithm")).isEqualTo("DENY_OVERRIDES");
        assertThat(model.getAttribute("resourcePage")).isEqualTo(Page.empty());
        assertThat(model.getAttribute("policyPage")).isEqualTo(Page.empty());
        assertThat(model.getAttribute("errorMessage")).isEqualTo("Something went wrong");
    }
}
