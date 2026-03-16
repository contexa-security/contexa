package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.ApprovalPolicy;
import io.contexa.contexacore.domain.entity.ApprovalPolicyEntity;
import org.springframework.cache.annotation.Cacheable;

public class ApprovalPolicyRepository {

    private final ApprovalPolicyJpaRepository jpaRepository;

    public ApprovalPolicyRepository(ApprovalPolicyJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Cacheable(value = "soarApprovalPolicies", key = "#actionName + ':' + #severity")
    public ApprovalPolicy findPolicyFor(String actionName, String severity) {
        return jpaRepository.findByActionNameAndSeverity(actionName, severity)
                .map(this::toDto)
                .or(() -> jpaRepository.findByActionNameIsNullAndSeverity(severity).map(this::toDto))
                .or(() -> jpaRepository.findByActionNameAndSeverityIsNull(actionName).map(this::toDto))
                .or(() -> jpaRepository.findByActionNameIsNullAndSeverityIsNull().map(this::toDto))
                .orElse(null);
    }

    private ApprovalPolicy toDto(ApprovalPolicyEntity entity) {
        return new ApprovalPolicy(
                entity.getRequiredApprovers(),
                entity.getRequiredRoles(),
                entity.getTimeoutMinutes(),
                entity.isAutoApproveOnTimeout()
        );
    }
}
