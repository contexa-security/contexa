package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.ApprovalPolicy;
import io.contexa.contexacore.domain.entity.ApprovalPolicyEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import java.util.List;

public class ApprovalPolicyRepository {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalPolicyRepository.class);
    private final ApprovalPolicyJpaRepository jpaRepository;

    private static final ApprovalPolicy FALLBACK_DEFAULT_POLICY = new ApprovalPolicy(1, List.of("ROLE_SOAR_ADMIN"), 60, false);

    public ApprovalPolicyRepository(ApprovalPolicyJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Cacheable(value = "soarApprovalPolicies", key = "#actionName + ':' + #severity")
    public ApprovalPolicy findPolicyFor(String actionName, String severity) {
        logger.debug("Finding approval policy for action: '{}', severity: '{}'", actionName, severity);

        return jpaRepository.findByActionNameAndSeverity(actionName, severity)
                .map(this::toDto)
                
                .or(() -> jpaRepository.findByActionNameIsNullAndSeverity(severity).map(this::toDto))
                
                .or(() -> jpaRepository.findByActionNameAndSeverityIsNull(actionName).map(this::toDto))
                
                .or(() -> jpaRepository.findByActionNameIsNullAndSeverityIsNull().map(this::toDto))
                
                .orElseGet(() -> {
                    logger.warn("No specific approval policy found for action '{}', severity '{}'. Returning fallback default policy.", actionName, severity);
                    return FALLBACK_DEFAULT_POLICY;
                });
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
