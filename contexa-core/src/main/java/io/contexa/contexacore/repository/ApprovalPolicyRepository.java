package io.contexa.contexacore.repository;

import io.contexa.contexacore.domain.ApprovalPolicy;
import io.contexa.contexacore.domain.entity.ApprovalPolicyEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * SOAR 승인 정책을 조회하는 서비스.
 * 데이터베이스에서 정책을 조회하고, 결과를 캐싱하여 성능을 최적화한다.
 */
@Component
public class ApprovalPolicyRepository {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalPolicyRepository.class);
    private final ApprovalPolicyJpaRepository jpaRepository;

    // 시스템의 최종 안전망 역할을 하는 하드코딩된 기본 정책
    private static final ApprovalPolicy FALLBACK_DEFAULT_POLICY = new ApprovalPolicy(1, List.of("ROLE_SOAR_ADMIN"), 60, false);

    public ApprovalPolicyRepository(ApprovalPolicyJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    /**
     * 주어진 액션 이름과 심각도에 가장 적합한 승인 정책을 찾는다.
     * 조회 순서:
     * 1. 액션명 + 심각도 일치
     * 2. 심각도만 일치 (해당 심각도의 기본값)
     * 3. 액션명만 일치 (해당 액션의 기본값)
     * 4. 글로벌 기본값
     * 5. 하드코딩된 최종 기본값
     * @param actionName 조회할 액션의 이름
     * @param severity 조회할 위협의 심각도
     * @return 적용할 ApprovalPolicy
     */
    @Cacheable("soarApprovalPolicies")
    public ApprovalPolicy findPolicyFor(String actionName, String severity) {
        logger.debug("Finding approval policy for action: '{}', severity: '{}'", actionName, severity);

        // 1. 가장 구체적인 정책 조회 (액션명 + 심각도)
        return jpaRepository.findByActionNameAndSeverity(actionName, severity)
                .map(this::toDto)
                // 2. 심각도에 대한 기본 정책 조회
                .or(() -> jpaRepository.findByActionNameIsNullAndSeverity(severity).map(this::toDto))
                // 3. 액션에 대한 기본 정책 조회
                .or(() -> jpaRepository.findByActionNameAndSeverityIsNull(actionName).map(this::toDto))
                // 4. 글로벌 DB 기본 정책 조회
                .or(() -> jpaRepository.findByActionNameIsNullAndSeverityIsNull().map(this::toDto))
                // 5. 모든 조회 실패 시, 코드에 정의된 최종 안전망 정책 반환
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
