package io.contexa.contexaiam.security.xacml.pap.analysis;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto.DuplicateType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Detects duplicate policies based on target+condition+effect signature comparison.
 * Supports exact, semantic (hasRole/hasAuthority equivalence), subset,
 * and role hierarchy subsumption detection.
 */
@Slf4j
@RequiredArgsConstructor
public class PolicyDuplicateDetector {

    private final PolicyRepository policyRepository;
    private final RoleHierarchy roleHierarchy;
    private final MessageSource messageSource;

    private static final Pattern HAS_ROLE_PATTERN = Pattern.compile("hasRole\\(['\"]([^'\"]*)['\"]\\)");
    private static final Pattern HAS_AUTHORITY_PATTERN = Pattern.compile("hasAuthority\\(['\"]([^'\"]*)['\"]\\)");

    /**
     * Detect duplicate policies for a candidate policy.
     */
    public List<DuplicatePolicyDto> detect(Policy candidate) {
        return detect(candidate, policyRepository.findAllWithDetails());
    }

    public List<DuplicatePolicyDto> detect(Policy candidate, List<Policy> existingPolicies) {
        List<DuplicatePolicyDto> duplicates = new ArrayList<>();

        String candidateSignature = buildSignature(candidate);
        String candidateNormalizedSignature = buildNormalizedSignature(candidate);
        Set<String> candidateTargetKeys = extractTargetKeys(candidate);

        for (Policy existing : existingPolicies) {
            if (isSamePolicy(candidate, existing)) continue;
            if (!existing.getIsActive()) continue;

            // EXACT: identical signature
            String existingSignature = buildSignature(existing);
            if (candidateSignature.equals(existingSignature)) {
                duplicates.add(new DuplicatePolicyDto(
                        msg("msg.policy.duplicate.exact"),
                        List.of(existing.getId()),
                        candidateSignature, DuplicateType.EXACT));
                continue;
            }

            // SEMANTIC: hasRole('X') == hasAuthority('ROLE_X')
            String existingNormalized = buildNormalizedSignature(existing);
            if (candidateNormalizedSignature.equals(existingNormalized)) {
                duplicates.add(new DuplicatePolicyDto(
                        msg("msg.policy.duplicate.semantic"),
                        List.of(existing.getId()),
                        candidateNormalizedSignature, DuplicateType.SEMANTIC));
                continue;
            }

            // SUBSET: same targets + same effect, existing conditions are superset
            if (candidate.getEffect() == existing.getEffect()) {
                Set<String> existingTargetKeys = extractTargetKeys(existing);
                if (existingTargetKeys.containsAll(candidateTargetKeys) && !candidateTargetKeys.isEmpty()) {
                    Set<String> candidateConditions = extractNormalizedConditions(candidate);
                    Set<String> existingConditions = extractNormalizedConditions(existing);
                    if (existingConditions.containsAll(candidateConditions) && !candidateConditions.isEmpty()) {
                        duplicates.add(new DuplicatePolicyDto(
                                msg("msg.policy.duplicate.subset"),
                                List.of(existing.getId()),
                                existingSignature, DuplicateType.SUBSET));
                        continue;
                    }
                }

                // HIERARCHY_SUBSUME: same targets + same effect, candidate roles are subsumed by existing via hierarchy
                if (hasOverlappingTargets(candidateTargetKeys, existingTargetKeys)) {
                    String subsumptionReason = checkHierarchySubsumption(candidate, existing);
                    if (subsumptionReason != null) {
                        duplicates.add(new DuplicatePolicyDto(
                                subsumptionReason,
                                List.of(existing.getId()),
                                existingSignature, DuplicateType.HIERARCHY_SUBSUME));
                    }
                }
            }
        }
        return duplicates;
    }

    /**
     * Check if the candidate policy's roles are already covered by the existing policy
     * through role hierarchy. e.g., existing has hasRole(USER), candidate has hasRole(ADMIN),
     * and ADMIN > USER -> ADMIN already inherits USER's access, so candidate is redundant.
     */
    private String checkHierarchySubsumption(Policy candidate, Policy existing) {
        Set<String> candidateRoles = extractRolesFromPolicy(candidate);
        Set<String> existingRoles = extractRolesFromPolicy(existing);

        if (candidateRoles.isEmpty() || existingRoles.isEmpty()) return null;

        for (String candidateRole : candidateRoles) {
            Collection<? extends GrantedAuthority> reachable =
                    roleHierarchy.getReachableGrantedAuthorities(
                            List.of(new SimpleGrantedAuthority(candidateRole)));
            Set<String> reachableNames = reachable.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

            if (reachableNames.containsAll(existingRoles)) {
                String existingRoleStr = String.join(", ", existingRoles);
                return messageSource.getMessage("msg.policy.duplicate.hierarchy",
                        new Object[]{candidateRole, existingRoleStr, existing.getName()},
                        LocaleContextHolder.getLocale());
            }
        }
        return null;
    }

    /**
     * Extract role names (normalized to ROLE_ prefix) from policy conditions.
     */
    private Set<String> extractRolesFromPolicy(Policy policy) {
        Set<String> roles = new HashSet<>();
        for (var rule : policy.getRules()) {
            for (PolicyCondition condition : rule.getConditions()) {
                String expr = condition.getExpression();
                Matcher roleMatcher = HAS_ROLE_PATTERN.matcher(expr);
                while (roleMatcher.find()) {
                    String role = roleMatcher.group(1);
                    roles.add(role.startsWith("ROLE_") ? role : "ROLE_" + role);
                }
                Matcher authMatcher = HAS_AUTHORITY_PATTERN.matcher(expr);
                while (authMatcher.find()) {
                    String auth = authMatcher.group(1);
                    if (auth.startsWith("ROLE_")) {
                        roles.add(auth);
                    }
                }
            }
        }
        return roles;
    }

    private boolean hasOverlappingTargets(Set<String> targets1, Set<String> targets2) {
        for (String t1 : targets1) {
            for (String t2 : targets2) {
                if (t1.equals(t2)) return true;
                String[] parts1 = t1.split(":");
                String[] parts2 = t2.split(":");
                if (parts1.length >= 2 && parts2.length >= 2 && parts1[1].equals(parts2[1])) {
                    return true;
                }
            }
        }
        return false;
    }

    private String buildSignature(Policy policy) {
        String targets = extractTargetKeys(policy).stream().sorted().collect(Collectors.joining("|"));
        String conditions = extractConditions(policy).stream().sorted().collect(Collectors.joining("|"));
        String raw = policy.getEffect() + ":" + targets + ":" + conditions;
        return sha256(raw);
    }

    private String buildNormalizedSignature(Policy policy) {
        String targets = extractTargetKeys(policy).stream().sorted().collect(Collectors.joining("|"));
        String conditions = extractNormalizedConditions(policy).stream().sorted().collect(Collectors.joining("|"));
        String raw = policy.getEffect() + ":" + targets + ":" + conditions;
        return sha256(raw);
    }

    private Set<String> extractTargetKeys(Policy policy) {
        return policy.getTargets().stream()
                .map(t -> t.getTargetType() + ":"
                        + t.getTargetIdentifier() + ":"
                        + (t.getHttpMethod() != null ? t.getHttpMethod().toUpperCase() : "ANY"))
                .collect(Collectors.toSet());
    }

    private Set<String> extractConditions(Policy policy) {
        return policy.getRules().stream()
                .flatMap(r -> r.getConditions().stream())
                .map(PolicyCondition::getExpression)
                .map(String::trim)
                .collect(Collectors.toSet());
    }

    private Set<String> extractNormalizedConditions(Policy policy) {
        return policy.getRules().stream()
                .flatMap(r -> r.getConditions().stream())
                .map(PolicyCondition::getExpression)
                .map(this::normalizeExpression)
                .collect(Collectors.toSet());
    }

    /**
     * Normalize SpEL to detect semantic equivalence.
     * hasRole('ADMIN') -> hasAuthority('ROLE_ADMIN')
     */
    private String normalizeExpression(String expression) {
        String normalized = expression.trim();
        Matcher matcher = HAS_ROLE_PATTERN.matcher(normalized);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String roleName = matcher.group(1);
            String replacement = roleName.startsWith("ROLE_")
                    ? "hasAuthority('" + roleName + "')"
                    : "hasAuthority('ROLE_" + roleName + "')";
            matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private String msg(String code) {
        return messageSource.getMessage(code, null, LocaleContextHolder.getLocale());
    }

    private boolean isSamePolicy(Policy candidate, Policy existing) {
        return candidate.getId() != null && candidate.getId().equals(existing.getId());
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            return input;
        }
    }
}
