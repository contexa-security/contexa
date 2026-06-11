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
package io.contexa.contexaiam.security.xacml.pap.analysis;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto.DuplicateType;
import io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyValidationReport;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Unified policy validation service that combines conflict and duplicate detection.
 * Results are exposed to admin UI for review.
 */
@Slf4j
@RequiredArgsConstructor
public class PolicyValidationService {

    private final PolicyConflictAnalyzer conflictAnalyzer;
    private final PolicyDuplicateDetector duplicateDetector;
    private final PolicyRepository policyRepository;
    private final MessageSource messageSource;

    /**
     * Validate a candidate policy before creation or update.
     * Returns conflicts, duplicates, and whether creation is allowed.
     */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PolicyValidationReport validate(Policy candidate) {
        List<PolicyConflictDto> conflicts = conflictAnalyzer.analyze(candidate);
        List<DuplicatePolicyDto> duplicates = duplicateDetector.detect(candidate);

        boolean hasCritical = conflicts.stream()
                .anyMatch(c -> c.severity() == PolicyConflictDto.Severity.CRITICAL);

        boolean hasExactDuplicate = duplicates.stream()
                .anyMatch(d -> d.type() == DuplicateType.EXACT);

        boolean canCreate = !hasCritical && !hasExactDuplicate;
        String blockedReason = null;
        if (hasCritical) {
            blockedReason = messageSource.getMessage("msg.policy.validation.blocked.critical",
                    null, LocaleContextHolder.getLocale());
        } else if (hasExactDuplicate) {
            blockedReason = messageSource.getMessage("msg.policy.validation.blocked.duplicate",
                    null, LocaleContextHolder.getLocale());
        }

        return new PolicyValidationReport(conflicts, duplicates, canCreate, blockedReason);
    }

    /**
     * Validate against a provided list of existing policies (for batch creation).
     */
    public PolicyValidationReport validate(Policy candidate, List<Policy> existingPolicies) {
        List<PolicyConflictDto> conflicts = conflictAnalyzer.analyze(candidate, existingPolicies);
        List<DuplicatePolicyDto> duplicates = duplicateDetector.detect(candidate, existingPolicies);

        boolean hasCritical = conflicts.stream()
                .anyMatch(c -> c.severity() == PolicyConflictDto.Severity.CRITICAL);
        boolean hasExactDuplicate = duplicates.stream()
                .anyMatch(d -> d.type() == DuplicateType.EXACT);
        boolean canCreate = !hasCritical && !hasExactDuplicate;
        String blockedReason = null;
        if (hasCritical) {
            blockedReason = messageSource.getMessage("msg.policy.validation.blocked.critical",
                    null, LocaleContextHolder.getLocale());
        } else if (hasExactDuplicate) {
            blockedReason = messageSource.getMessage("msg.policy.validation.blocked.duplicate",
                    null, LocaleContextHolder.getLocale());
        }
        return new PolicyValidationReport(conflicts, duplicates, canCreate, blockedReason);
    }

    /**
     * Validate all existing policies against each other.
     * Returns full system health report for admin dashboard.
     */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public FullValidationReport validateAll() {
        List<Policy> allPolicies = policyRepository.findAllWithDetails();
        List<PolicyConflictDto> allConflicts = new ArrayList<>();
        List<DuplicatePolicyDto> allDuplicates = new ArrayList<>();

        for (Policy policy : allPolicies) {
            if (!policy.getIsActive()) {
                continue;
            }
            allConflicts.addAll(conflictAnalyzer.analyze(policy, allPolicies));
            allDuplicates.addAll(duplicateDetector.detect(policy, allPolicies));
        }

        // Deduplicate symmetric conflicts (A vs B == B vs A)
        List<PolicyConflictDto> deduplicatedConflicts = deduplicateConflicts(allConflicts);

        String healthStatus = FullValidationReport.computeHealthStatus(deduplicatedConflicts);

        return new FullValidationReport(
                allPolicies.size(), healthStatus,
                deduplicatedConflicts, allDuplicates);
    }

    private List<PolicyConflictDto> deduplicateConflicts(List<PolicyConflictDto> conflicts) {
        List<PolicyConflictDto> result = new ArrayList<>();
        for (PolicyConflictDto conflict : conflicts) {
            boolean isDuplicate = result.stream().anyMatch(existing ->
                    Objects.equals(existing.newPolicyId(), conflict.existingPolicyId())
                            && Objects.equals(existing.existingPolicyId(), conflict.newPolicyId()));
            if (!isDuplicate) {
                result.add(conflict);
            }
        }
        return result;
    }
}
