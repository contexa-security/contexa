package io.contexa.contexaiam.repository;

import io.contexa.contexaiam.domain.entity.policy.PolicyVersion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface PolicyVersionRepository extends JpaRepository<PolicyVersion, Long> {

    List<PolicyVersion> findByPolicyIdOrderByVersionNumberDesc(Long policyId);

    Optional<PolicyVersion> findByPolicyIdAndVersionNumber(Long policyId, int versionNumber);

    @Query("SELECT COALESCE(MAX(v.versionNumber), 0) FROM PolicyVersion v WHERE v.policyId = :policyId")
    int findMaxVersionNumber(@Param("policyId") Long policyId);

    long countByPolicyId(Long policyId);

    void deleteByPolicyId(Long policyId);
}
