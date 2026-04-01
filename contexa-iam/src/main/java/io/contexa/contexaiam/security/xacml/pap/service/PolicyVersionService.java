package io.contexa.contexaiam.security.xacml.pap.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.domain.dto.PolicyDto;
import io.contexa.contexaiam.domain.entity.policy.Policy;
import io.contexa.contexaiam.domain.entity.policy.PolicyVersion;
import io.contexa.contexaiam.domain.entity.policy.PolicyVersion.ChangeType;
import io.contexa.contexaiam.repository.PolicyVersionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Manages policy version history, rollback, and diff comparison.
 */
@Slf4j
@RequiredArgsConstructor
public class PolicyVersionService {

    private final PolicyVersionRepository versionRepository;
    private final ObjectMapper objectMapper;
    private final ModelMapper modelMapper;

    /**
     * Create a version snapshot for the given policy.
     */
    @Transactional
    public PolicyVersion createVersion(Policy policy, ChangeType changeType, String reason) {
        int nextVersion = versionRepository.findMaxVersionNumber(policy.getId()) + 1;

        String snapshot;
        try {
            PolicyDto dto = modelMapper.map(policy, PolicyDto.class);
            snapshot = objectMapper.writeValueAsString(dto);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize policy snapshot for policy ID: {}", policy.getId(), e);
            snapshot = "{}";
        }

        String principal = extractCurrentUsername();

        PolicyVersion version = PolicyVersion.builder()
                .policyId(policy.getId())
                .versionNumber(nextVersion)
                .snapshotJson(snapshot)
                .changeType(changeType)
                .changedBy(principal)
                .changeReason(reason)
                .build();

        return versionRepository.save(version);
    }

    /**
     * Get version history for a policy, ordered by version number descending.
     */
    @Transactional(readOnly = true)
    public List<PolicyVersion> getVersions(Long policyId) {
        return versionRepository.findByPolicyIdOrderByVersionNumberDesc(policyId);
    }

    /**
     * Get a specific version snapshot.
     */
    @Transactional(readOnly = true)
    public Optional<PolicyVersion> getVersion(Long policyId, int versionNumber) {
        return versionRepository.findByPolicyIdAndVersionNumber(policyId, versionNumber);
    }

    /**
     * Deserialize a version snapshot back to PolicyDto.
     */
    public Optional<PolicyDto> deserializeSnapshot(PolicyVersion version) {
        try {
            PolicyDto dto = objectMapper.readValue(version.getSnapshotJson(), PolicyDto.class);
            return Optional.of(dto);
        } catch (JsonProcessingException e) {
            log.error("Failed to deserialize policy snapshot for version: {}", version.getId(), e);
            return Optional.empty();
        }
    }

    /**
     * Compare two versions and return field-level differences.
     */
    @Transactional(readOnly = true)
    @SuppressWarnings("unchecked")
    public List<Map<String, String>> compareVersions(Long policyId, int v1, int v2) {
        PolicyVersion version1 = versionRepository.findByPolicyIdAndVersionNumber(policyId, v1)
                .orElseThrow(() -> new IllegalArgumentException("Version " + v1 + " not found"));
        PolicyVersion version2 = versionRepository.findByPolicyIdAndVersionNumber(policyId, v2)
                .orElseThrow(() -> new IllegalArgumentException("Version " + v2 + " not found"));

        try {
            Map<String, Object> map1 = objectMapper.readValue(version1.getSnapshotJson(), Map.class);
            Map<String, Object> map2 = objectMapper.readValue(version2.getSnapshotJson(), Map.class);

            List<Map<String, String>> changes = new ArrayList<>();
            Set<String> allKeys = new HashSet<>();
            allKeys.addAll(map1.keySet());
            allKeys.addAll(map2.keySet());

            for (String key : allKeys) {
                Object val1 = map1.get(key);
                Object val2 = map2.get(key);
                if (!Objects.equals(val1, val2)) {
                    changes.add(Map.of(
                            "field", key,
                            "before", val1 != null ? val1.toString() : "",
                            "after", val2 != null ? val2.toString() : ""));
                }
            }
            return changes;
        } catch (JsonProcessingException e) {
            log.error("Failed to compare versions {} and {} for policy {}", v1, v2, policyId, e);
            return List.of();
        }
    }

    private String extractCurrentUsername() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getName() != null) {
            return auth.getName();
        }
        return "SYSTEM";
    }
}
