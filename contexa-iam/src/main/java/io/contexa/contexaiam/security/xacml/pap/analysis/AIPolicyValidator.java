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

    private static final Pattern HAS_AUTHORITY_PATTERN = Pattern.compile("hasAuthority\\('([^']*)'\\)");
    private static final int LEAST_PRIVILEGE_THRESHOLD = 10;

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
                    "All referenced roles and permissions exist");
        }
        return new ValidationItem("Referential Integrity", CheckResult.FAIL,
                "Missing: " + String.join(", ", missing));
    }

    private ValidationItem checkConflicts(Policy policy) {
        List<PolicyConflictDto> conflicts = conflictAnalyzer.analyze(policy);
        if (conflicts.isEmpty()) {
            return new ValidationItem("Conflict Check", CheckResult.PASS,
                    "No conflicts detected");
        }

        boolean hasCritical = conflicts.stream()
                .anyMatch(c -> c.severity() == PolicyConflictDto.Severity.CRITICAL);
        if (hasCritical) {
            return new ValidationItem("Conflict Check", CheckResult.FAIL,
                    conflicts.size() + " conflict(s) including CRITICAL");
        }
        return new ValidationItem("Conflict Check", CheckResult.WARNING,
                conflicts.size() + " conflict(s) detected");
    }

    private ValidationItem checkDuplicates(Policy policy) {
        List<DuplicatePolicyDto> duplicates = duplicateDetector.detect(policy);
        if (duplicates.isEmpty()) {
            return new ValidationItem("Duplicate Check", CheckResult.PASS,
                    "No duplicates detected");
        }

        boolean hasExact = duplicates.stream()
                .anyMatch(d -> d.type() == DuplicatePolicyDto.DuplicateType.EXACT);
        if (hasExact) {
            return new ValidationItem("Duplicate Check", CheckResult.FAIL,
                    "Exact duplicate exists");
        }
        return new ValidationItem("Duplicate Check", CheckResult.WARNING,
                duplicates.size() + " potential duplicate(s)");
    }

    private ValidationItem checkLeastPrivilege(Policy policy) {
        Set<String> authorities = extractReferencedAuthorities(policy);
        if (authorities.size() > LEAST_PRIVILEGE_THRESHOLD) {
            return new ValidationItem("Least Privilege", CheckResult.WARNING,
                    authorities.size() + " authorities referenced (threshold: " + LEAST_PRIVILEGE_THRESHOLD + ")");
        }
        return new ValidationItem("Least Privilege", CheckResult.PASS,
                authorities.size() + " authorities referenced");
    }

    private ValidationItem checkDangerousPatterns(Policy policy) {
        List<String> dangers = new ArrayList<>();

        for (var rule : policy.getRules()) {
            for (PolicyCondition condition : rule.getConditions()) {
                String expr = condition.getExpression();
                if ("permitAll".equals(expr.trim()) && policy.getEffect() == Policy.Effect.ALLOW) {
                    dangers.add("permitAll with ALLOW effect grants unrestricted access");
                }
                if ("denyAll".equals(expr.trim()) && policy.getEffect() == Policy.Effect.DENY) {
                    dangers.add("denyAll with DENY effect blocks all access");
                }
                if (expr.contains("isAuthenticated()") && !expr.contains("hasAuthority")
                        && !expr.contains("hasRole") && policy.getEffect() == Policy.Effect.ALLOW) {
                    dangers.add("isAuthenticated() alone without role/permission check");
                }
            }
        }

        if (dangers.isEmpty()) {
            return new ValidationItem("Dangerous Patterns", CheckResult.PASS,
                    "No dangerous patterns detected");
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
