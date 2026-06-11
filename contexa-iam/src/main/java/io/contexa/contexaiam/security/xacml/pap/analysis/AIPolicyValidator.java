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
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.security.xacml.pap.dto.AIPolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.AIPolicyValidationReport.CheckResult;
import io.contexa.contexaiam.security.xacml.pap.dto.AIPolicyValidationReport.ValidationItem;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates AI-generated policies before approval.
 * Checks referential integrity, conflicts, duplicates, least privilege, and dangerous patterns.
 */
@Slf4j
@RequiredArgsConstructor
public class AIPolicyValidator {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final PolicyConflictAnalyzer conflictAnalyzer;
    private final PolicyDuplicateDetector duplicateDetector;
    private final MessageSource messageSource;

    private static final Pattern HAS_AUTHORITY_PATTERN = Pattern.compile("hasAuthority\\('([^']*)'\\)");
    private static final int LEAST_PRIVILEGE_THRESHOLD = 10;

    private String i18n(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

    /**
     * Validate an AI-generated policy for approval readiness.
     */
    public AIPolicyValidationReport validate(Policy policy) {
        List<ValidationItem> items = new ArrayList<>();

        items.add(checkReferentialIntegrity(policy));
        items.add(checkConflicts(policy));
        items.add(checkDuplicates(policy));
        items.add(checkLeastPrivilege(policy));
        items.add(checkDangerousPatterns(policy));

        boolean hasFail = items.stream().anyMatch(i -> i.result() == CheckResult.FAIL);
        String blockedReason = null;
        if (hasFail) {
            blockedReason = items.stream()
                    .filter(i -> i.result() == CheckResult.FAIL)
                    .map(i -> i.checkName() + ": " + i.detail())
                    .reduce((a, b) -> a + "; " + b)
                    .orElse("Validation failed");
        }

        return new AIPolicyValidationReport(items, !hasFail, blockedReason);
    }

    private ValidationItem checkReferentialIntegrity(Policy policy) {
        Set<String> referencedAuthorities = extractReferencedAuthorities(policy);
        List<String> missing = new ArrayList<>();

        for (String authority : referencedAuthorities) {
            if (authority.startsWith("ROLE_")) {
                String roleName = authority;
                if (roleRepository.findByRoleName(roleName).isEmpty()) {
                    missing.add(roleName);
                }
            } else {
                if (permissionRepository.findByName(authority).isEmpty()) {
                    missing.add(authority);
                }
            }
        }

        if (missing.isEmpty()) {
            return new ValidationItem("Referential Integrity", CheckResult.PASS,
                    i18n("msg.policy.ai.check.referential"));
        }
        return new ValidationItem("Referential Integrity", CheckResult.FAIL,
                i18n("msg.policy.ai.check.referential.missing", String.join(", ", missing)));
    }

    private ValidationItem checkConflicts(Policy policy) {
        List<PolicyConflictDto> conflicts = conflictAnalyzer.analyze(policy);
        if (conflicts.isEmpty()) {
            return new ValidationItem("Conflict Check", CheckResult.PASS,
                    i18n("msg.policy.ai.check.conflict.none"));
        }

        boolean hasCritical = conflicts.stream()
                .anyMatch(c -> c.severity() == PolicyConflictDto.Severity.CRITICAL);
        if (hasCritical) {
            return new ValidationItem("Conflict Check", CheckResult.FAIL,
                    i18n("msg.policy.ai.check.conflict.critical", conflicts.size()));
        }
        return new ValidationItem("Conflict Check", CheckResult.WARNING,
                i18n("msg.policy.ai.check.conflict.found", conflicts.size()));
    }

    private ValidationItem checkDuplicates(Policy policy) {
        List<DuplicatePolicyDto> duplicates = duplicateDetector.detect(policy);
        if (duplicates.isEmpty()) {
            return new ValidationItem("Duplicate Check", CheckResult.PASS,
                    i18n("msg.policy.ai.check.duplicate.none"));
        }

        boolean hasExact = duplicates.stream()
                .anyMatch(d -> d.type() == DuplicatePolicyDto.DuplicateType.EXACT);
        if (hasExact) {
            return new ValidationItem("Duplicate Check", CheckResult.FAIL,
                    i18n("msg.policy.ai.check.duplicate.exact"));
        }
        return new ValidationItem("Duplicate Check", CheckResult.WARNING,
                i18n("msg.policy.ai.check.duplicate.found", duplicates.size()));
    }

    private ValidationItem checkLeastPrivilege(Policy policy) {
        Set<String> authorities = extractReferencedAuthorities(policy);
        if (authorities.size() > LEAST_PRIVILEGE_THRESHOLD) {
            return new ValidationItem("Least Privilege", CheckResult.WARNING,
                    i18n("msg.policy.ai.check.privilege.warn", authorities.size(), LEAST_PRIVILEGE_THRESHOLD));
        }
        return new ValidationItem("Least Privilege", CheckResult.PASS,
                i18n("msg.policy.ai.check.privilege.ok", authorities.size()));
    }

    private ValidationItem checkDangerousPatterns(Policy policy) {
        List<String> dangers = new ArrayList<>();

        for (var rule : policy.getRules()) {
            for (PolicyCondition condition : rule.getConditions()) {
                String expr = condition.getExpression();
                if ("permitAll".equals(expr.trim()) && policy.getEffect() == Policy.Effect.ALLOW) {
                    dangers.add(i18n("msg.policy.ai.check.danger.permitall"));
                }
                if ("denyAll".equals(expr.trim()) && policy.getEffect() == Policy.Effect.DENY) {
                    dangers.add(i18n("msg.policy.ai.check.danger.denyall"));
                }
                if (expr.contains("isAuthenticated()") && !expr.contains("hasAuthority")
                        && !expr.contains("hasRole") && policy.getEffect() == Policy.Effect.ALLOW) {
                    dangers.add(i18n("msg.policy.ai.check.danger.authonly"));
                }
            }
        }

        if (dangers.isEmpty()) {
            return new ValidationItem("Dangerous Patterns", CheckResult.PASS,
                    i18n("msg.policy.ai.check.danger.none"));
        }
        return new ValidationItem("Dangerous Patterns", CheckResult.WARNING,
                String.join("; ", dangers));
    }

    private Set<String> extractReferencedAuthorities(Policy policy) {
        Set<String> authorities = new HashSet<>();
        for (var rule : policy.getRules()) {
            for (PolicyCondition condition : rule.getConditions()) {
                Matcher matcher = HAS_AUTHORITY_PATTERN.matcher(condition.getExpression());
                while (matcher.find()) {
                    authorities.add(matcher.group(1));
                }
            }
        }
        return authorities;
    }
}
