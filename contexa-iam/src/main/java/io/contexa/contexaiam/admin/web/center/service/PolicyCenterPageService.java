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
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterPolicyRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyResourceSearchRequest;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.analysis.PolicyValidationService;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class PolicyCenterPageService {

    /** K92: the policies of a conflict or a duplicate the policy check found, the ones the dashboard counts. */
    public static final String HEALTH_ISSUES = "ISSUES";
    /** The rows of a page of the policy list, the newest policy first. */
    static final int POLICY_PAGE_SIZE = 10;
    static final Sort POLICY_ORDER = Sort.by(Sort.Direction.DESC, "id");

    private final ResourceRegistryService resourceRegistryService;
    private final PolicyService policyService;
    private final PolicyCombiningProperties policyCombiningProperties;
    /** K92: the policy check the dashboard counts the conflicts and duplicates of; without it that filter lists none. */
    private PolicyValidationService policyValidation;

    public void setPolicyValidation(PolicyValidationService policyValidation) {
        this.policyValidation = policyValidation;
    }

    /** The list without the filter of the policy check, as before K92. */
    public void populatePolicyCenterModel(
            Model model,
            String tab,
            PolicyResourceSearchRequest criteria,
            Pageable pageable,
            String policyKeyword,
            String approvalStatus,
            Boolean activeFilter,
            int policyPage) {
        populatePolicyCenterModel(model, tab, criteria, pageable, policyKeyword, approvalStatus, activeFilter, null,
                policyPage);
    }

    /**
     * @param health {@link #HEALTH_ISSUES} to list only the policies of a conflict or a duplicate the policy check found
     *               (K92), from the report the dashboard counts them from; any other value lists every policy
     */
    public void populatePolicyCenterModel(
            Model model,
            String tab,
            PolicyResourceSearchRequest criteria,
            Pageable pageable,
            String policyKeyword,
            String approvalStatus,
            Boolean activeFilter,
            String health,
            int policyPage) {
        model.addAttribute("activePage", "policy-center");
        model.addAttribute("activeTab", tab);
        model.addAttribute("combiningAlgorithm", policyCombiningProperties.getCombiningAlgorithm().name());

        Page<ManagedResource> resourcePage = resourceRegistryService.findResources(criteria.toCriteria(), pageable);
        Set<String> serviceOwners = resourceRegistryService.getAllServiceOwners();
        model.addAttribute("resourcePage", resourcePage);
        model.addAttribute("serviceOwners", serviceOwners);
        model.addAttribute("criteria", criteria);

        model.addAttribute("policy", PolicyCenterPolicyRequest.emptyForForm());

        // K139: a page before the first is the first; a page after the last is the last
        Pageable policyPageable = PageRequest.of(Math.max(0, policyPage), POLICY_PAGE_SIZE, POLICY_ORDER);
        Policy.ApprovalStatus approvalStatusEnum = parseApprovalStatus(approvalStatus);
        boolean healthIssues = HEALTH_ISSUES.equalsIgnoreCase(health == null ? "" : health.trim());
        Set<Long> ids = healthIssues ? issuePolicies(model) : null;
        Page<Policy> policyPageResult = policies(policyKeyword, approvalStatusEnum, activeFilter, ids, policyPageable);
        if (policyPageResult.getTotalPages() > 0 && policyPageResult.getNumber() >= policyPageResult.getTotalPages()) {
            policyPageResult = policies(policyKeyword, approvalStatusEnum, activeFilter, ids,
                    PageRequest.of(policyPageResult.getTotalPages() - 1, POLICY_PAGE_SIZE, POLICY_ORDER));
        }
        model.addAttribute("policyPage", policyPageResult);
        model.addAttribute("policyKeyword", policyKeyword);
        // K108 beside: the filters stay with the list's pages and its search as the values the address carries
        model.addAttribute("approvalStatusFilter", approvalStatusEnum != null ? approvalStatusEnum.name() : null);
        model.addAttribute("approvalStatuses", Policy.ApprovalStatus.values());
        model.addAttribute("activeFilter", activeFilter);
        model.addAttribute("healthFilter", healthIssues ? HEALTH_ISSUES : null);
    }

    private Page<Policy> policies(String keyword, Policy.ApprovalStatus approvalStatus, Boolean activeFilter,
                                  Set<Long> onlyIds, Pageable pageable) {
        return onlyIds != null ? policyService.searchPolicies(keyword, approvalStatus, activeFilter, onlyIds, pageable)
                : policyService.searchPolicies(keyword, approvalStatus, activeFilter, pageable);
    }

    /**
     * K92: the policies of the conflicts and the duplicates of the report the dashboard counts them from, and the
     * counts of the report for the list's band; none when the check could not run.
     */
    private Set<Long> issuePolicies(Model model) {
        Set<Long> ids = new LinkedHashSet<>();
        if (policyValidation == null) {
            model.addAttribute("healthUnavailable", true);
            return ids;
        }
        try {
            FullValidationReport report = policyValidation.validateAllForDashboard();
            for (PolicyConflictDto conflict : report.conflicts()) {
                addId(ids, conflict.newPolicyId());
                addId(ids, conflict.existingPolicyId());
            }
            for (DuplicatePolicyDto duplicate : report.duplicates()) {
                if (duplicate.policyIds() != null) {
                    duplicate.policyIds().forEach(id -> addId(ids, id));
                }
            }
            model.addAttribute("healthConflicts", report.conflicts().size());
            model.addAttribute("healthDuplicates", report.duplicates().size());
        } catch (RuntimeException e) {
            // As on the dashboard: a check that could not run counts nothing, it does not say zero.
            log.error("[PolicyCenter] The policy check could not run for the list's filter", e);
            model.addAttribute("healthUnavailable", true);
            ids.clear();
        }
        return ids;
    }

    private static void addId(Set<Long> ids, Long id) {
        if (id != null) {
            ids.add(id);
        }
    }

    public void populatePolicyCenterErrorModel(
            Model model,
            String tab,
            PolicyResourceSearchRequest criteria,
            String errorMessage) {
        model.addAttribute("activePage", "policy-center");
        model.addAttribute("activeTab", tab);
        model.addAttribute("combiningAlgorithm", policyCombiningProperties.getCombiningAlgorithm().name());
        model.addAttribute("resourcePage", Page.empty());
        model.addAttribute("serviceOwners", Collections.emptySet());
        model.addAttribute("criteria", criteria);
        model.addAttribute("policy", PolicyCenterPolicyRequest.emptyForForm());
        model.addAttribute("policyPage", Page.empty());
        model.addAttribute("errorMessage", errorMessage);
    }

    private Policy.ApprovalStatus parseApprovalStatus(String approvalStatus) {
        if (approvalStatus == null || approvalStatus.isBlank()) {
            return null;
        }
        try {
            return Policy.ApprovalStatus.valueOf(approvalStatus);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }
}
