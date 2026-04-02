package io.contexa.contexaiam.security.xacml.pap.analysis;

import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyCondition;
import io.contexa.contexaiam.domain.entity.policy.PolicyTarget;
import io.contexa.contexaiam.repository.PolicyRepository;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto.DuplicateType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Detects duplicate policies based on target+condition+effect signature comparison.
 * Supports exact, semantic (hasRole/hasAuthority equivalence), and subset detection.
 */
@Slf4j
@RequiredArgsConstructor
public class PolicyDuplicateDetector {

    private final PolicyRepository policyRepository;
    private static final Pattern HAS_ROLE_PATTERN = Pattern.compile("hasRole\\('([^']*)'\\)");

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
            if (isSamePolicy(candidate, existing)) {
                continue;
            }
            if (!existing.getIsActive()) {
                continue;
            }

            // EXACT: identical signature
            String existingSignature = buildSignature(existing);
            if (candidateSignature.equals(existingSignature)) {
                duplicates.add(new DuplicatePolicyDto(
                        "Exact duplicate: identical targets, conditions, and effect",
                        List.of(existing.getId()),
                        candidateSignature, DuplicateType.EXACT));
                continue;
            }

            // SEMANTIC: hasRole('X') == hasAuthority('ROLE_X')
            String existingNormalized = buildNormalizedSignature(existing);
            if (candidateNormalizedSignature.equals(existingNormalized)) {
                duplicates.add(new DuplicatePolicyDto(
                        "Semantic duplicate: equivalent after SpEL normalization (hasRole/hasAuthority)",
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
                                "Subset: existing policy already covers this policy's targets and conditions",
                                List.of(existing.getId()),
                                existingSignature, DuplicateType.SUBSET));
                    }
                }
            }
        }
        return duplicates;
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
