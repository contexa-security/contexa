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
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto.DuplicateType;
import io.contexa.contexaiam.security.xacml.pdp.evaluation.SpelLiteral;
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
import java.util.function.Function;
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

    /** The argument is a single-quoted literal (group 1, quotes doubled) or a double-quoted one (group 2). */
    private static final String ARGUMENT = "\\((?:" + SpelLiteral.PATTERN + "|\"([^\"]*)\")\\)";
    private static final Pattern HAS_ROLE_PATTERN = Pattern.compile("hasRole" + ARGUMENT);
    private static final Pattern HAS_AUTHORITY_PATTERN = Pattern.compile("hasAuthority" + ARGUMENT);

    private static String argument(Matcher matcher) {
        return matcher.group(1) != null ? SpelLiteral.unquote(matcher.group(1)) : matcher.group(2);
    }

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
     * D65: the duplicates of every active policy among the others, exactly as {@link #detect(Policy, List)} gives them
     * for each active policy in turn, in the same order. The signatures, target keys and conditions of each policy are
     * worked out once instead of once per pair, and a policy is compared only with the active policies that can be a
     * duplicate of it: the same signature (exact), the same normalized signature (semantic), or, with the same effect,
     * a target of its own (subset) or the identifier of one (role hierarchy). Those are the only ways a pair is
     * reported, so the result is the one of comparing every pair.
     */
    public List<DuplicatePolicyDto> detectAll(List<Policy> policies) {
        List<Facts> facts = new ArrayList<>(policies.size());
        Map<String, List<Integer>> bySignature = new HashMap<>();
        Map<String, List<Integer>> byNormalizedSignature = new HashMap<>();
        Map<Policy.Effect, Map<String, List<Integer>>> byTarget = new HashMap<>();
        Map<Policy.Effect, Map<String, List<Integer>>> byIdentifier = new HashMap<>();
        for (int index = 0; index < policies.size(); index++) {
            Policy policy = policies.get(index);
            Facts policyFacts = new Facts(policy);
            facts.add(policyFacts);
            if (!policy.getIsActive()) {
                continue;
            }
            put(bySignature, policyFacts.signature, index);
            put(byNormalizedSignature, policyFacts.normalizedSignature, index);
            Map<String, List<Integer>> targets = byTarget.computeIfAbsent(policy.getEffect(), e -> new HashMap<>());
            Map<String, List<Integer>> identifiers =
                    byIdentifier.computeIfAbsent(policy.getEffect(), e -> new HashMap<>());
            for (String target : policyFacts.targetKeys) {
                put(targets, target, index);
                String identifier = identifierOf(target);
                if (identifier != null) {
                    put(identifiers, identifier, index);
                }
            }
        }

        Map<String, Set<String>> reachable = new HashMap<>();
        List<DuplicatePolicyDto> duplicates = new ArrayList<>();
        for (int index = 0; index < policies.size(); index++) {
            Policy candidate = policies.get(index);
            if (!candidate.getIsActive()) {
                continue;
            }
            Facts candidateFacts = facts.get(index);
            TreeSet<Integer> others = new TreeSet<>();
            others.addAll(bySignature.getOrDefault(candidateFacts.signature, List.of()));
            others.addAll(byNormalizedSignature.getOrDefault(candidateFacts.normalizedSignature, List.of()));
            Map<String, List<Integer>> sameEffectTargets = byTarget.getOrDefault(candidate.getEffect(), Map.of());
            Map<String, List<Integer>> sameEffectIdentifiers =
                    byIdentifier.getOrDefault(candidate.getEffect(), Map.of());
            for (String target : candidateFacts.targetKeys) {
                others.addAll(sameEffectTargets.getOrDefault(target, List.of()));
                String identifier = identifierOf(target);
                if (identifier != null) {
                    others.addAll(sameEffectIdentifiers.getOrDefault(identifier, List.of()));
                }
            }
            for (int other : others) {
                Policy existing = policies.get(other);
                if (isSamePolicy(candidate, existing)) {
                    continue;
                }
                DuplicatePolicyDto duplicate = compare(candidate, candidateFacts, existing, facts.get(other),
                        role -> reachable.computeIfAbsent(role, this::reachableFrom));
                if (duplicate != null) {
                    duplicates.add(duplicate);
                }
            }
        }
        return duplicates;
    }

    /** The comparison of {@link #detect(Policy, List)} for one pair, on facts worked out beforehand. */
    private DuplicatePolicyDto compare(Policy candidate, Facts candidateFacts, Policy existing, Facts existingFacts,
                                       Function<String, Set<String>> reachable) {
        if (candidateFacts.signature.equals(existingFacts.signature)) {
            return new DuplicatePolicyDto(msg("msg.policy.duplicate.exact"), List.of(existing.getId()),
                    candidateFacts.signature, DuplicateType.EXACT);
        }
        if (candidateFacts.normalizedSignature.equals(existingFacts.normalizedSignature)) {
            return new DuplicatePolicyDto(msg("msg.policy.duplicate.semantic"), List.of(existing.getId()),
                    candidateFacts.normalizedSignature, DuplicateType.SEMANTIC);
        }
        if (candidate.getEffect() != existing.getEffect()) {
            return null;
        }
        if (existingFacts.targetKeys.containsAll(candidateFacts.targetKeys) && !candidateFacts.targetKeys.isEmpty()
                && existingFacts.normalizedConditions.containsAll(candidateFacts.normalizedConditions)
                && !candidateFacts.normalizedConditions.isEmpty()) {
            return new DuplicatePolicyDto(msg("msg.policy.duplicate.subset"), List.of(existing.getId()),
                    existingFacts.signature, DuplicateType.SUBSET);
        }
        if (hasOverlappingTargets(candidateFacts.targetKeys, existingFacts.targetKeys)) {
            String subsumptionReason = checkHierarchySubsumption(candidateFacts.roles, existingFacts.roles, existing,
                    reachable);
            if (subsumptionReason != null) {
                return new DuplicatePolicyDto(subsumptionReason, List.of(existing.getId()), existingFacts.signature,
                        DuplicateType.HIERARCHY_SUBSUME);
            }
        }
        return null;
    }

    /** What the comparisons read of a policy, worked out once. */
    private final class Facts {

        final String signature;
        final String normalizedSignature;
        final Set<String> targetKeys;
        final Set<String> normalizedConditions;
        final Set<String> roles;

        Facts(Policy policy) {
            this.signature = buildSignature(policy);
            this.normalizedSignature = buildNormalizedSignature(policy);
            this.targetKeys = extractTargetKeys(policy);
            this.normalizedConditions = extractNormalizedConditions(policy);
            this.roles = extractRolesFromPolicy(policy);
        }
    }

    /** The part of a target key that {@link #hasOverlappingTargets} compares besides the whole key. */
    private static String identifierOf(String targetKey) {
        String[] parts = targetKey.split(":");
        return parts.length >= 2 ? parts[1] : null;
    }

    private static void put(Map<String, List<Integer>> map, String key, int policy) {
        List<Integer> policies = map.computeIfAbsent(key, k -> new ArrayList<>());
        if (policies.isEmpty() || policies.get(policies.size() - 1) != policy) {
            policies.add(policy);
        }
    }

    private Set<String> reachableFrom(String role) {
        return roleHierarchy.getReachableGrantedAuthorities(List.of(new SimpleGrantedAuthority(role))).stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }

    /**
     * Check if the candidate policy's roles are already covered by the existing policy
     * through role hierarchy. e.g., existing has hasRole(USER), candidate has hasRole(ADMIN),
     * and ADMIN > USER -> ADMIN already inherits USER's access, so candidate is redundant.
     */
    private String checkHierarchySubsumption(Policy candidate, Policy existing) {
        return checkHierarchySubsumption(extractRolesFromPolicy(candidate), extractRolesFromPolicy(existing), existing,
                this::reachableFrom);
    }

    private String checkHierarchySubsumption(Set<String> candidateRoles, Set<String> existingRoles, Policy existing,
                                             Function<String, Set<String>> reachable) {
        if (candidateRoles.isEmpty() || existingRoles.isEmpty()) return null;

        for (String candidateRole : candidateRoles) {
            Set<String> reachableNames = reachable.apply(candidateRole);

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
                    String role = argument(roleMatcher);
                    roles.add(role.startsWith("ROLE_") ? role : "ROLE_" + role);
                }
                Matcher authMatcher = HAS_AUTHORITY_PATTERN.matcher(expr);
                while (authMatcher.find()) {
                    String auth = argument(authMatcher);
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
                        + (t.getHttpMethod() != null ? t.getHttpMethod().toUpperCase(Locale.ROOT) : "ANY"))
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
            String roleName = argument(matcher);
            String replacement = SpelLiteral.hasAuthority(roleName.startsWith("ROLE_") ? roleName : "ROLE_" + roleName);
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
