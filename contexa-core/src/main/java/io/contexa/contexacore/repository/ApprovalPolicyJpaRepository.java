package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.entity.ApprovalPolicyEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ApprovalPolicyJpaRepository extends JpaRepository<ApprovalPolicyEntity, Long> {

    Optional<ApprovalPolicyEntity> findByActionNameAndSeverity(String actionName, String severity);

    Optional<ApprovalPolicyEntity> findByActionNameIsNullAndSeverity(String severity);

    Optional<ApprovalPolicyEntity> findByActionNameAndSeverityIsNull(String actionName);

    Optional<ApprovalPolicyEntity> findByActionNameIsNullAndSeverityIsNull();
}