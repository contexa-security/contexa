package io.contexa.contexaiam.admin.web.center.service;

import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexaiam.admin.web.center.dto.PolicyCenterPolicyRequest;
import io.contexa.contexaiam.admin.web.center.dto.PolicyResourceSearchRequest;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.resource.service.ResourceRegistryService;
import io.contexa.contexaiam.security.xacml.pap.service.PolicyService;
import io.contexa.contexaiam.security.xacml.pdp.combining.PolicyCombiningProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;

import java.util.Collections;
import java.util.Set;

@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class PolicyCenterPageService {

    private final ResourceRegistryService resourceRegistryService;
    private final PolicyService policyService;
    private final PolicyCombiningProperties policyCombiningProperties;

    public void populatePolicyCenterModel(
            Model model,
            String tab,
            PolicyResourceSearchRequest criteria,
            Pageable pageable,
            String policyKeyword,
            String approvalStatus,
            Boolean activeFilter,
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

        Pageable policyPageable = PageRequest.of(policyPage, 10, Sort.by(Sort.Direction.DESC, "id"));
        Policy.ApprovalStatus approvalStatusEnum = parseApprovalStatus(approvalStatus);
        Page<Policy> policyPageResult = policyService.searchPolicies(
                policyKeyword,
                approvalStatusEnum,
                activeFilter,
                policyPageable);
        model.addAttribute("policyPage", policyPageResult);
        model.addAttribute("policyKeyword", policyKeyword);
        model.addAttribute("approvalStatusFilter", approvalStatus);
        model.addAttribute("activeFilter", activeFilter);
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
