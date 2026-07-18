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
import java.util.List;
import java.util.Set;
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
        return method.toUpperCase();
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

    private record TargetOverlap(TargetSignature candidate, TargetSignature existing, OverlapType type) {
    }

    private enum OverlapType {
        NONE,
        EXACT,
        WILDCARD,
        METHOD_PARTIAL
    }
}
