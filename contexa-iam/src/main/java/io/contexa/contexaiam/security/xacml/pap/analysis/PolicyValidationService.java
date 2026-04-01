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

    /**
     * Validate a candidate policy before creation or update.
     * Returns conflicts, duplicates, and whether creation is allowed.
     */
    @Transactional(readOnly = true)
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
            blockedReason = "CRITICAL conflict detected with existing policy";
        } else if (hasExactDuplicate) {
            blockedReason = "Exact duplicate policy already exists";
        }

        return new PolicyValidationReport(conflicts, duplicates, canCreate, blockedReason);
    }

    /**
     * Validate all existing policies against each other.
     * Returns full system health report for admin dashboard.
     */
    @Transactional(readOnly = true)
    public FullValidationReport validateAll() {
        List<Policy> allPolicies = policyRepository.findAllWithDetails();
        List<PolicyConflictDto> allConflicts = new ArrayList<>();
        List<DuplicatePolicyDto> allDuplicates = new ArrayList<>();

        for (Policy policy : allPolicies) {
            if (!policy.getIsActive()) {
                continue;
            }
            List<PolicyConflictDto> conflicts = conflictAnalyzer.analyze(policy);
            allConflicts.addAll(conflicts);

            List<DuplicatePolicyDto> duplicates = duplicateDetector.detect(policy);
            allDuplicates.addAll(duplicates);
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
