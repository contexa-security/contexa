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

import java.util.Locale;
import java.util.Objects;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto.Severity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.util.AntPathMatcher;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Multi-dimensional policy conflict analyzer.
 * Detects conflicts across target patterns, HTTP methods, and effect oppositions.
 */
@Slf4j
@RequiredArgsConstructor
public class PolicyConflictAnalyzer {

    private final PolicyRepository policyRepository;
    private final MessageSource messageSource;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    /**
     * Analyze conflicts between a new/updated policy and all existing policies.
     *
     * @param candidatePolicy the policy being created or updated
     * @return list of detected conflicts with severity levels
     */
    public List<PolicyConflictDto> analyze(Policy candidatePolicy) {
        return analyze(candidatePolicy, policyRepository.findAllWithDetails());
    }

    public List<PolicyConflictDto> analyze(Policy candidatePolicy, List<Policy> existingPolicies) {
        List<PolicyConflictDto> conflicts = new ArrayList<>();

        Set<TargetSignature> candidateTargets = extractTargetSignatures(candidatePolicy);
        if (candidateTargets.isEmpty()) {
            return conflicts;
        }

        for (Policy existing : existingPolicies) {
            if (isSamePolicy(candidatePolicy, existing)) {
                continue;
            }
            if (!existing.getIsActive()) {
                continue;
            }

            Set<TargetSignature> existingTargets = extractTargetSignatures(existing);
            List<TargetOverlap> overlaps = findTargetOverlaps(candidateTargets, existingTargets);

            for (TargetOverlap overlap : overlaps) {
                boolean effectConflict = candidatePolicy.getEffect() != existing.getEffect();

                if (effectConflict) {
                    Severity severity = classifySeverity(overlap);
                    conflicts.add(new PolicyConflictDto(
                            candidatePolicy.getId(), candidatePolicy.getName(),
                            existing.getId(), existing.getName(),
                            buildConflictDescription(overlap, candidatePolicy.getEffect(), existing.getEffect()),
                            severity));
                }
            }
        }
        return conflicts;
    }

    /**
     * D65: the conflicts of every active policy with the others, exactly as {@link #analyze(Policy, List)} gives them
     * for each active policy in turn, in the same order. Comparing every policy with every other one made the dashboard
     * take eleven seconds with two thousand policies. Each policy's targets are read once, and a policy is compared
     * only with the active policies of another effect whose targets can overlap its own (see {@link OverlapIndex}).
     */
    public List<PolicyConflictDto> analyzeAll(List<Policy> policies) {
        List<Set<TargetSignature>> targets = new ArrayList<>(policies.size());
        Map<Policy.Effect, OverlapIndex> byEffect = new HashMap<>();
        for (int index = 0; index < policies.size(); index++) {
            Policy policy = policies.get(index);
            Set<TargetSignature> policyTargets = extractTargetSignatures(policy);
            targets.add(policyTargets);
            if (policy.getIsActive()) {
                byEffect.computeIfAbsent(policy.getEffect(), effect -> new OverlapIndex()).add(index, policyTargets);
            }
        }

        List<PolicyConflictDto> conflicts = new ArrayList<>();
        for (int index = 0; index < policies.size(); index++) {
            Policy candidatePolicy = policies.get(index);
            if (!candidatePolicy.getIsActive()) {
                continue;
            }
            Set<TargetSignature> candidateTargets = targets.get(index);
            if (candidateTargets.isEmpty()) {
                continue;
            }
            TreeSet<Integer> others = new TreeSet<>();
            byEffect.forEach((effect, overlapIndex) -> {
                // Only a policy of another effect is reported as a conflict.
                if (candidatePolicy.getEffect() != effect) {
                    overlapIndex.collect(candidateTargets, others);
                }
            });
            for (int other : others) {
                Policy existing = policies.get(other);
                if (isSamePolicy(candidatePolicy, existing)) {
                    continue;
                }
                for (TargetOverlap overlap : findTargetOverlaps(candidateTargets, targets.get(other))) {
                    conflicts.add(new PolicyConflictDto(
                            candidatePolicy.getId(), candidatePolicy.getName(),
                            existing.getId(), existing.getName(),
                            buildConflictDescription(overlap, candidatePolicy.getEffect(), existing.getEffect()),
                            classifySeverity(overlap)));
                }
            }
        }
        return conflicts;
    }

    private List<TargetOverlap> findTargetOverlaps(Set<TargetSignature> candidateTargets,
                                                    Set<TargetSignature> existingTargets) {
        List<TargetOverlap> overlaps = new ArrayList<>();

        for (TargetSignature candidate : candidateTargets) {
            if (!"URL".equals(candidate.targetType)) {
                for (TargetSignature existing : existingTargets) {
                    if (candidate.targetType.equals(existing.targetType)
                            && candidate.identifier.equals(existing.identifier)) {
                        overlaps.add(new TargetOverlap(candidate, existing, OverlapType.EXACT));
                    }
                }
                continue;
            }

            for (TargetSignature existing : existingTargets) {
                if (!"URL".equals(existing.targetType)) {
                    continue;
                }

                OverlapType overlapType = detectUrlOverlap(candidate.identifier, existing.identifier);
                if (overlapType == OverlapType.NONE) {
                    continue;
                }

                if (!httpMethodsOverlap(candidate.httpMethod, existing.httpMethod)) {
                    continue;
                }

                boolean partialMethodOverlap = isPartialMethodOverlap(candidate.httpMethod, existing.httpMethod);
                if (partialMethodOverlap && overlapType == OverlapType.EXACT) {
                    overlapType = OverlapType.METHOD_PARTIAL;
                }

                overlaps.add(new TargetOverlap(candidate, existing, overlapType));
            }
        }
        return overlaps;
    }

    private OverlapType detectUrlOverlap(String candidatePath, String existingPath) {
        if (candidatePath.equals(existingPath)) {
            return OverlapType.EXACT;
        }

        boolean candidateMatchesExisting = safeMatch(candidatePath, existingPath);
        boolean existingMatchesCandidate = safeMatch(existingPath, candidatePath);

        if (candidateMatchesExisting && existingMatchesCandidate) {
            return OverlapType.EXACT;
        }
        if (candidateMatchesExisting || existingMatchesCandidate) {
            return OverlapType.WILDCARD;
        }

        if (hasCommonPrefix(candidatePath, existingPath)) {
            boolean candidateIsWildcard = candidatePath.contains("*") || candidatePath.contains("{");
            boolean existingIsWildcard = existingPath.contains("*") || existingPath.contains("{");
            if (candidateIsWildcard && existingIsWildcard) {
                return OverlapType.WILDCARD;
            }
        }

        return OverlapType.NONE;
    }

    private boolean safeMatch(String pattern, String path) {
        try {
            return pathMatcher.match(pattern, path);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean hasCommonPrefix(String path1, String path2) {
        String[] segments1 = path1.split("/");
        String[] segments2 = path2.split("/");
        int minLen = Math.min(segments1.length, segments2.length);

        int meaningfulCommon = 0;
        for (int i = 0; i < minLen; i++) {
            String s1 = segments1[i];
            String s2 = segments2[i];
            if (s1.isEmpty() && s2.isEmpty()) {
                continue;
            }
            if (s1.equals(s2) && !s1.contains("*") && !s1.contains("{")) {
                meaningfulCommon++;
            } else {
                break;
            }
        }
        return meaningfulCommon >= 2;
    }

    private boolean httpMethodsOverlap(String method1, String method2) {
        if (isAnyMethod(method1) || isAnyMethod(method2)) {
            return true;
        }
        return Objects.equals(normalizeMethod(method1), normalizeMethod(method2));
    }

    private boolean isPartialMethodOverlap(String method1, String method2) {
        if (isAnyMethod(method1) != isAnyMethod(method2)) {
            return true;
        }
        return false;
    }

    private boolean isAnyMethod(String method) {
        return method == null || "ANY".equalsIgnoreCase(method) || "ALL".equalsIgnoreCase(method);
    }

    private String normalizeMethod(String method) {
        if (method == null) {
            return "ANY";
        }
        return method.toUpperCase(Locale.ROOT);
    }

    private Severity classifySeverity(TargetOverlap overlap) {
        return switch (overlap.type) {
            case EXACT -> Severity.CRITICAL;
            case WILDCARD -> Severity.HIGH;
            case METHOD_PARTIAL -> Severity.MEDIUM;
            default -> Severity.LOW;
        };
    }

    private String buildConflictDescription(TargetOverlap overlap, Policy.Effect candidateEffect,
                                             Policy.Effect existingEffect) {
        String overlapDesc = switch (overlap.type) {
            case EXACT -> i18n("msg.policy.conflict.exact");
            case WILDCARD -> i18n("msg.policy.conflict.wildcard");
            case METHOD_PARTIAL -> i18n("msg.policy.conflict.method");
            default -> i18n("msg.policy.conflict.potential");
        };

        return i18n("msg.policy.conflict.description",
                candidateEffect, existingEffect, overlapDesc,
                overlap.candidate.httpMethod != null ? overlap.candidate.httpMethod : "ANY",
                overlap.candidate.identifier,
                overlap.existing.httpMethod != null ? overlap.existing.httpMethod : "ANY",
                overlap.existing.identifier);
    }

    private String i18n(String code, Object... args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }

    private boolean isSamePolicy(Policy candidate, Policy existing) {
        return candidate.getId() != null && candidate.getId().equals(existing.getId());
    }

    private Set<TargetSignature> extractTargetSignatures(Policy policy) {
        return policy.getTargets().stream()
                .map(t -> new TargetSignature(t.getTargetType(), t.getTargetIdentifier(), t.getHttpMethod()))
                .collect(Collectors.toSet());
    }

    private record TargetSignature(String targetType, String identifier, String httpMethod) {
    }

    /**
     * The targets of the policies of one effect, kept so that a target finds every target it can overlap without
     * looking at the others. A target of another type overlaps only one of its type with the same identifier. Two URL
     * patterns overlap ({@link #findTargetOverlaps}) only when one matches the other or they share two leading literal
     * segments and both have a wildcard. A match needs the literal segments a pattern starts with to be the first
     * segments of the other, so the literal prefixes of the two (the segments before the first one with *, ? or {) are
     * one a prefix of the other: a pattern is found under every prefix of its literal prefix, and by its first two
     * segments when it has a wildcard. What this finds is checked by the same comparison as before.
     */
    private static final class OverlapIndex {

        private final Map<String, List<Integer>> sameIdentifier = new HashMap<>();
        private final Map<String, List<Integer>> literalPrefix = new HashMap<>();
        private final Map<String, List<Integer>> underPrefix = new HashMap<>();
        private final Map<String, List<Integer>> leadingSegments = new HashMap<>();

        void add(int policy, Set<TargetSignature> targets) {
            for (TargetSignature target : targets) {
                if (!"URL".equals(target.targetType)) {
                    put(sameIdentifier, target.targetType + '\u0000' + target.identifier, policy);
                    continue;
                }
                List<String> prefix = literalPrefix(target.identifier);
                put(literalPrefix, key(prefix, prefix.size()), policy);
                for (int length = 0; length <= prefix.size(); length++) {
                    put(underPrefix, key(prefix, length), policy);
                }
                String leading = leadingSegments(target.identifier);
                if (leading != null) {
                    put(leadingSegments, leading, policy);
                }
            }
        }

        /** Adds the policies whose targets can overlap one of the candidate's targets. */
        void collect(Set<TargetSignature> candidateTargets, Set<Integer> into) {
            for (TargetSignature target : candidateTargets) {
                if (!"URL".equals(target.targetType)) {
                    into.addAll(sameIdentifier.getOrDefault(target.targetType + '\u0000' + target.identifier, List.of()));
                    continue;
                }
                List<String> prefix = literalPrefix(target.identifier);
                into.addAll(underPrefix.getOrDefault(key(prefix, prefix.size()), List.of()));
                for (int length = 0; length < prefix.size(); length++) {
                    into.addAll(literalPrefix.getOrDefault(key(prefix, length), List.of()));
                }
                String leading = leadingSegments(target.identifier);
                if (leading != null) {
                    into.addAll(leadingSegments.getOrDefault(leading, List.of()));
                }
            }
        }

        private static void put(Map<String, List<Integer>> map, String key, int policy) {
            List<Integer> policies = map.computeIfAbsent(key, k -> new ArrayList<>());
            if (policies.isEmpty() || policies.get(policies.size() - 1) != policy) {
                policies.add(policy);
            }
        }

        /** The segments before the first one with a wildcard, as the path matcher splits a pattern (no empty ones). */
        private static List<String> literalPrefix(String identifier) {
            List<String> prefix = new ArrayList<>();
            for (String segment : identifier.split("/")) {
                if (segment.isEmpty()) {
                    continue;
                }
                if (segment.indexOf('*') >= 0 || segment.indexOf('?') >= 0 || segment.indexOf('{') >= 0) {
                    break;
                }
                prefix.add(segment);
            }
            return prefix;
        }

        /** The first two segments of a pattern with a wildcard, when neither has one: the shared prefix it can have. */
        private static String leadingSegments(String identifier) {
            if (identifier.indexOf('*') < 0 && identifier.indexOf('{') < 0) {
                return null;
            }
            List<String> segments = new ArrayList<>(2);
            for (String segment : identifier.split("/")) {
                if (segment.isEmpty()) {
                    continue;
                }
                if (segment.contains("*") || segment.contains("{")) {
                    return null;
                }
                segments.add(segment);
                if (segments.size() == 2) {
                    return key(segments, 2);
                }
            }
            return null;
        }

        private static String key(List<String> segments, int length) {
            return String.join("/", segments.subList(0, length));
        }
    }

    private record TargetOverlap(TargetSignature candidate, TargetSignature existing, OverlapType type) {
    }

    private enum OverlapType {
        NONE,
        EXACT,
        WILDCARD,
        METHOD_PARTIAL
    }
}
