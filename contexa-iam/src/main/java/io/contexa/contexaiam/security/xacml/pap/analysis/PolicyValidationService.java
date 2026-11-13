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

import java.util.Objects;

import io.contexa.contexaiam.domain.dto.ConditionDto;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.dto.RuleDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto.DuplicateType;
import io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.PolicyExpressionValidator;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.UnsafePolicyExpressionException;
import io.contexa.contexaiam.security.xacml.prp.PolicyGeneration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

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

    /** How long the dashboard's report is kept at most, for changes no reload follows (the role hierarchy). */
    private static final Duration DASHBOARD_REPORT_LIFETIME = Duration.ofMinutes(5);

    private final Object dashboardReportLock = new Object();
    private volatile DashboardReport dashboardReport;

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

    /**
     * D65: the report of {@link #validateAll()} for the dashboard. The full validation compares every policy with every
     * other one, and the dashboard asked for it on every load: with two thousand policies a load took eleven seconds.
     * The report is worked out again only when the policies have been reloaded since (every change of the policies
     * reloads them, on this node and on the others) or when it is five minutes old.
     */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public FullValidationReport validateAllForDashboard() {
        long generation = PolicyGeneration.current();
        DashboardReport kept = dashboardReport;
        if (kept != null && kept.isCurrent(generation)) {
            return kept.report();
        }
        synchronized (dashboardReportLock) {
            kept = dashboardReport;
            if (kept != null && kept.isCurrent(generation)) {
                return kept.report();
            }
            FullValidationReport report = validateAll();
            dashboardReport = new DashboardReport(generation, Instant.now(), report);
            return report;
        }
    }

    /**
     * D26: what a policy of the policy form needs to be created, as the policy service requires it: a name, an effect,
     * a target, and conditions it accepts. Empty when nothing is missing.
     */
    public List<String> missingForCreation(PolicyDto dto) {
        List<String> missing = missingNameAndEffect(dto.getName(), dto.getEffect());
        if (dto.getTargets() == null || dto.getTargets().isEmpty()) {
            missing.add(msg("msg.policy.validation.target.required"));
        }
        if (dto.getRules() != null) {
            for (RuleDto rule : dto.getRules()) {
                if (rule == null || rule.getConditions() == null) {
                    continue;
                }
                for (ConditionDto condition : rule.getConditions()) {
                    if (condition == null) {
                        continue;
                    }
                    try {
                        PolicyExpressionValidator.validate(condition.getExpression());
                    } catch (UnsafePolicyExpressionException e) {
                        missing.add(msg(e.getMessageKey(), e.getReason()));
                    }
                }
            }
        }
        return missing;
    }

    /**
     * D26: what a quick policy needs to be created, as the business policy service requires it: a name, an effect, and
     * a role, a permission or an expression chosen. Empty when nothing is missing.
     */
    public List<String> missingForQuickCreation(String name, Policy.Effect effect, boolean anythingChosen) {
        List<String> missing = missingNameAndEffect(name, effect);
        if (!anythingChosen) {
            missing.add(msg("msg.policy.validation.select.required"));
        }
        return missing;
    }

    /** The report of a candidate that cannot be created for what it lacks: it is compared with no other policy. */
    public static PolicyValidationReport blockedFor(List<String> missing) {
        return new PolicyValidationReport(List.of(), List.of(), false, String.join(" ", missing));
    }

    private List<String> missingNameAndEffect(String name, Policy.Effect effect) {
        List<String> missing = new ArrayList<>();
        if (name == null || name.isBlank()) {
            missing.add(msg("msg.policy.validation.name.required"));
        }
        if (effect == null) {
            missing.add(msg("msg.policy.validation.effect.required"));
        }
        return missing;
    }

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    private record DashboardReport(long generation, Instant madeAt, FullValidationReport report) {

        boolean isCurrent(long currentGeneration) {
            return generation == currentGeneration && madeAt.plus(DASHBOARD_REPORT_LIFETIME).isAfter(Instant.now());
        }
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
