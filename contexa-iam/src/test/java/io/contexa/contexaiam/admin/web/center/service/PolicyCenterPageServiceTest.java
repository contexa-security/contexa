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
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
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
import org.springframework.data.domain.Pageable;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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

    @Test
    @DisplayName("K92: the policy check's filter lists the policies of the dashboard's report, with its counts")
    void theHealthFilterListsThePoliciesOfTheDashboardsReport() {
        Model model = new ConcurrentModel();
        PolicyValidationService validation = mock(PolicyValidationService.class);
        service.setPolicyValidation(validation);
        when(policyCombiningProperties.getCombiningAlgorithm()).thenReturn(CombiningAlgorithm.DENY_OVERRIDES);
        when(resourceRegistryService.findResources(any(), any())).thenReturn(Page.empty());
        when(validation.validateAllForDashboard()).thenReturn(new FullValidationReport(6, "WARNING",
                List.of(new PolicyConflictDto(1L, "a", 2L, "b", "overlap"), new PolicyConflictDto(2L, "b", 3L, "c", "overlap")),
                List.of(new DuplicatePolicyDto("same", List.of(4L, 5L), "sig"))));
        Page<Policy> policyPage = new PageImpl<>(List.of(new Policy()));
        when(policyService.searchPolicies(isNull(), isNull(), eq(true), eq(Set.of(1L, 2L, 3L, 4L, 5L)), any()))
                .thenReturn(policyPage);

        service.populatePolicyCenterModel(model, "list", new PolicyResourceSearchRequest(), PageRequest.of(0, 10), null,
                null, true, "issues", 0);

        assertThat(model.getAttribute("policyPage")).isEqualTo(policyPage);
        assertThat(model.getAttribute("healthFilter")).isEqualTo("ISSUES");
        assertThat(model.getAttribute("healthConflicts")).isEqualTo(2);
        assertThat(model.getAttribute("healthDuplicates")).isEqualTo(1);
        assertThat(model.getAttribute("activeFilter")).isEqualTo(true);
        verify(policyService, never()).searchPolicies(any(), any(), any(), any(Pageable.class));
    }

    @Test
    @DisplayName("K92: a policy check that could not run lists no policy and says so, as the dashboard counts none")
    void aCheckThatCouldNotRunListsNone() {
        Model model = new ConcurrentModel();
        PolicyValidationService validation = mock(PolicyValidationService.class);
        service.setPolicyValidation(validation);
        when(policyCombiningProperties.getCombiningAlgorithm()).thenReturn(CombiningAlgorithm.DENY_OVERRIDES);
        when(resourceRegistryService.findResources(any(), any())).thenReturn(Page.empty());
        when(validation.validateAllForDashboard()).thenThrow(new IllegalStateException("the policies cannot be read"));
        when(policyService.searchPolicies(isNull(), isNull(), isNull(), eq(Set.of()), any())).thenReturn(Page.empty());

        service.populatePolicyCenterModel(model, "list", new PolicyResourceSearchRequest(), PageRequest.of(0, 10), null,
                "NOT_A_STATE", null, "ISSUES", 0);

        assertThat(model.getAttribute("healthUnavailable")).isEqualTo(true);
        assertThat(model.getAttribute("healthFilter")).isEqualTo("ISSUES");
        assertThat(model.getAttribute("approvalStatusFilter")).isNull();
    }

    @Test
    @DisplayName("K139: a page before the first is the first; a page after the last is the last")
    void aPageOutOfTheListIsItsEnd() {
        when(policyCombiningProperties.getCombiningAlgorithm()).thenReturn(CombiningAlgorithm.DENY_OVERRIDES);
        when(resourceRegistryService.findResources(any(), any())).thenReturn(Page.empty());
        when(policyService.searchPolicies(any(), any(), any(), any(Pageable.class))).thenAnswer(invocation ->
                new PageImpl<>(List.of(), invocation.getArgument(3, Pageable.class), 34));
        Model before = new ConcurrentModel();
        Model after = new ConcurrentModel();

        service.populatePolicyCenterModel(before, "list", new PolicyResourceSearchRequest(), PageRequest.of(0, 10), null,
                null, null, -1);
        service.populatePolicyCenterModel(after, "list", new PolicyResourceSearchRequest(), PageRequest.of(0, 10), null,
                null, null, 9);

        assertThat(((Page<?>) before.getAttribute("policyPage")).getNumber()).isZero();
        assertThat(((Page<?>) after.getAttribute("policyPage")).getNumber()).isEqualTo(3);
    }
}
